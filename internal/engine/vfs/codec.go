// codec.go — a read-write, os-backed SQLite VFS that encrypts every page with
// the SQLCipher-4 page format (github.com/hanzoai/sqlcipher), giving the pure-Go
// engine real at-rest encryption byte-compatible with C SQLCipher.
//
// It is the write side the vendored engine's stock vfs package leaves null (it fills
// only xRead/xFileSize/xClose (read-only). Here codecio wires xWrite/xTruncate/
// xSync too, backed by a real *os.File, and transforms page bytes with the codec
// on the way through.)
//
// # How it stays byte-compatible AND lets the engine's WAL round-trip
//
// SQLCipher's codec is normally a pager hook; here it is a VFS shim UNDER the
// pager, so the engine computes WAL frame checksums over the PLAINTEXT page, reserve
// region included. The codec overwrites that reserve with a fresh IV+HMAC on every
// write, so a naive decrypt would not reproduce the bytes the engine checksummed and
// WAL recovery would reject every frame. The fix, proven empirically: the engine
// zeros the full page buffer of NEW pages, and codecRead ZEROS the reserve of
// every page it returns — so every page the engine ever checksums has a zero reserve,
// the checksum is always taken over [data‖zeros], and the read-back reproduces it
// exactly. (the main database file carries no checksums, so zeroing the (pager-
// ignored) reserve there is invisible and the on-disk ciphertext is byte-identical
// to what C SQLCipher writes.
//
// # Fail-closed
//
// A wrong key or a tampered page fails Decrypt (HMAC) and is returned as an I/O
// error; plaintext is never produced. Rollback journals are refused (keyed
// databases run WAL-only); temp spill is kept in memory by the DSN. Plaintext
// never reaches disk.
package vfs

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/hanzoai/sqlcipher"
	sqlite3 "github.com/hanzoai/sqlite/internal/engine/lib"
	"github.com/hanzoai/sqlite/internal/libc"
)

// file kinds the codec handles distinctly.
const (
	kindMain = iota // main database: page 1 keeps the salt in the clear
	kindWAL         // write-ahead log: [32B hdr][24B frame hdr + page]*
)

// walHdr / frameHdr are the fixed WAL layout sizes (wal.c).
const (
	walHdr   = 32
	frameHdr = 24
)

// codecVFS is one keyed database's VFS instance, referenced from sqlite3_vfs
// pAppData. The DEK lives here and nowhere global; Close drops the reference.
type codecVFS struct {
	key  []byte // 32-byte DEK (raw SQLCipher key, no KDF)
	ps   int    // page size (SQLCipher default 4096)
	mu   sync.Mutex
	salt []byte // database salt, set when the main db is opened; shared with the WAL
	shm  shm    // in-process wal-index shared memory for this database
}

// shm is a database's WAL shared-memory (the wal-index). For a single-writer
// keyed store (MaxOpenConns(1)) it is heap memory owned by the one connection;
// SQLite reads and writes the wal-index through the region pointers xShmMap hands
// back, and rebuilds it from the -wal file after any unmap, so freeing it on close
// loses nothing. One shm per database (per codecVFS), shared by that database's
// connections; the single-writer cap makes the shm locks contention-free, so they
// are no-ops.
type shm struct {
	mu       sync.Mutex
	regions  []uintptr // C-allocated, zeroed wal-index regions
	szRegion int32
}

// codecState is the Go-side handle for one open file, referenced from the
// C-allocated file struct by token (addObject), the same indirection the vendored engine's
// read-only VFS uses to keep Go pointers out of C memory.
type codecState struct {
	f          *os.File
	codec      *sqlcipher.Codec
	kind       int
	ps         int
	delOnClose bool
	path       string
	vfs        *codecVFS // back-ref for the shared wal-index (shm)
}

// codecCFile is the C-visible file: SQLite treats *pFile as sqlite3_file (its
// first field is pMethods); handle indexes back to the codecState.
type codecCFile = struct {
	base   sqlite3_file
	handle uintptr
}

// codecio is this VFS's io_methods: read AND write, plus the shm (wal-index)
// methods (iVersion 2) that let WAL run on an in-process heap wal-index with no
// -shm file — the single-writer model keyed stores use.
var codecio sqlite3_io_methods

func init() {
	// iVersion 2 advertises the shm (wal-index) methods so WAL works — including
	// the DELETE→WAL conversion a new database goes through — without an external
	// -shm file. Everything is a single-writer heap wal-index.
	codecio.iVersion = 2
	codecio.xClose = fp1(codecClose)
	codecio.xRead = fpRW(codecRead)
	codecio.xWrite = fpRW(codecWrite)
	codecio.xTruncate = fpTrunc(codecTruncate)
	codecio.xSync = fpSync(codecSync)
	codecio.xFileSize = fpSize(codecFileSize)
	codecio.xLock = fpLock(vfsLock)                           // reused: no-op (single writer)
	codecio.xUnlock = fpLock(vfsUnlock)                       // reused: no-op
	codecio.xCheckReservedLock = fpSize(vfsCheckReservedLock) // reused: reports none
	codecio.xFileControl = fpFileCtl(vfsFileControl)          // reused: SQLITE_NOTFOUND
	codecio.xSectorSize = fp1(codecSectorSize)
	codecio.xDeviceCharacteristics = fp1(codecDeviceCharacteristics)
	codecio.xShmMap = fpShmMap(codecShmMap)
	codecio.xShmLock = fpShmLock(codecShmLock)
	codecio.xShmBarrier = fp0(codecShmBarrier)
	codecio.xShmUnmap = fpSync(codecShmUnmap)
}

// --- Go-func → C function-pointer reinterprets, one per signature. This is the
// exact idiom ccgo emits (see Xsqlite3_fsFS); the engine's TLS calling convention
// makes a Go func of the matching shape directly callable as a C function pointer.

func fp1(f func(*libc.TLS, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr) int32
	}{f}))
}
func fpRW(f func(*libc.TLS, uintptr, uintptr, int32, sqlite_int64) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32, sqlite_int64) int32
	}{f}))
}
func fpTrunc(f func(*libc.TLS, uintptr, sqlite_int64) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, sqlite_int64) int32
	}{f}))
}
func fpSync(f func(*libc.TLS, uintptr, int32) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{f}))
}
func fpSize(f func(*libc.TLS, uintptr, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr) int32
	}{f}))
}
func fpLock(f func(*libc.TLS, uintptr, int32) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32) int32
	}{f}))
}
func fpFileCtl(f func(*libc.TLS, uintptr, int32, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, uintptr) int32
	}{f}))
}
func fpOpen(f func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32
	}{f}))
}
func fpDelete(f func(*libc.TLS, uintptr, uintptr, int32) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32) int32
	}{f}))
}
func fpAccess(f func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32
	}{f}))
}
func fpVoid3(f func(*libc.TLS, uintptr, int32, uintptr)) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, uintptr)
	}{f}))
}
func fpVfs2(f func(*libc.TLS, uintptr, uintptr) uintptr) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr) uintptr
	}{f}))
}
func fpVfs3(f func(*libc.TLS, uintptr, uintptr, uintptr) uintptr) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, uintptr) uintptr
	}{f}))
}
func fpRand(f func(*libc.TLS, uintptr, int32, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, uintptr) int32
	}{f}))
}
func fpShmMap(f func(*libc.TLS, uintptr, int32, int32, int32, uintptr) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, int32, int32, uintptr) int32
	}{f}))
}
func fpShmLock(f func(*libc.TLS, uintptr, int32, int32, int32) int32) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, int32, int32, int32) int32
	}{f}))
}
func fp0(f func(*libc.TLS, uintptr)) uintptr {
	return *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr)
	}{f}))
}

// Register creates and registers a VFS bound to dek and returns its name (for
// `?vfs=<name>`) and a closer that unregisters it and drops the key. dek must be
// a 32-byte raw SQLCipher key. One instance per open database.
func Register(dek []byte) (name string, closer func() error, err error) {
	if len(dek) != sqlcipher.KeySize {
		return "", nil, fmt.Errorf("sqlcipher/vfs: key must be %d bytes, got %d", sqlcipher.KeySize, len(dek))
	}
	tls := libc.NewTLS()
	o := &codecVFS{key: append([]byte(nil), dek...), ps: sqlcipher.DefaultPageSize}
	h := addObject(o)
	name = fmt.Sprintf("sqlcipher-%x", h)
	cname, err := libc.CString(name)
	if err != nil {
		removeObject(h)
		tls.Close()
		return "", nil, err
	}

	p := libc.Xmalloc(tls, libc.Tsize_t(unsafe.Sizeof(sqlite3_vfs{})))
	if p == 0 {
		removeObject(h)
		libc.Xfree(tls, cname)
		tls.Close()
		return "", nil, fmt.Errorf("sqlcipher/vfs: out of memory")
	}
	*(*sqlite3_vfs)(unsafe.Pointer(p)) = sqlite3_vfs{
		iVersion:      1,
		szOsFile:      int32(unsafe.Sizeof(codecCFile{})),
		mxPathname:    1024,
		zName:         cname,
		pAppData:      h,
		xOpen:         fpOpen(codecOpen),
		xDelete:       fpDelete(codecDelete),
		xAccess:       fpAccess(codecAccess),
		xFullPathname: fpAccess(vfsFullPathname),
		xDlOpen:       fpVfs2(vfsDlOpen),
		xDlError:      fpVoid3(vfsDlError),
		xDlSym:        fpVfs3(vfsDlSym),
		xDlClose: *(*uintptr)(unsafe.Pointer(&struct {
			f func(*libc.TLS, uintptr, uintptr)
		}{vfsDlClose})),
		xRandomness:  fpRand(vfsRandomness),
		xSleep:       fpSync(vfsSleep),
		xCurrentTime: fpSize(vfsCurrentTime),
	}
	if rc := sqlite3.Xsqlite3_vfs_register(tls, p, libc.Bool32(false)); rc != sqlite3.SQLITE_OK {
		removeObject(h)
		libc.Xfree(tls, cname)
		libc.Xfree(tls, p)
		tls.Close()
		return "", nil, fmt.Errorf("sqlcipher/vfs: register: %d", rc)
	}

	var once sync.Once
	closer = func() error {
		once.Do(func() {
			sqlite3.Xsqlite3_vfs_unregister(tls, p)
			o.mu.Lock()
			for i := range o.key { // wipe the DEK
				o.key[i] = 0
			}
			o.mu.Unlock()
			removeObject(h)
			libc.Xfree(tls, cname)
			libc.Xfree(tls, p)
			tls.Close()
		})
		return nil
	}
	return name, closer, nil
}

func codecOpen(tls *libc.TLS, pVfs, zName, pFile uintptr, flags int32, pOutFlags uintptr) int32 {
	if zName == 0 {
		return sqlite3.SQLITE_CANTOPEN
	}
	o := getObject((*sqlite3_vfs)(unsafe.Pointer(pVfs)).pAppData).(*codecVFS)
	name := libc.GoString(zName)

	// Keyed databases run WAL-only; a rollback journal would put plaintext page
	// images on disk, so refuse it (fail closed). The DSN sets journal_mode=WAL,
	// so this never fires in normal operation.
	if flags&sqlite3.SQLITE_OPEN_MAIN_JOURNAL != 0 {
		return sqlite3.SQLITE_CANTOPEN
	}

	oflags := os.O_RDWR
	if flags&sqlite3.SQLITE_OPEN_CREATE != 0 {
		oflags |= os.O_CREATE
	}
	f, err := os.OpenFile(name, oflags, 0o600)
	if err != nil {
		return sqlite3.SQLITE_CANTOPEN
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return sqlite3.SQLITE_CANTOPEN
	}

	kind := kindWAL
	if flags&sqlite3.SQLITE_OPEN_MAIN_DB != 0 {
		kind = kindMain
	}

	o.mu.Lock()
	if kind == kindMain {
		if st.Size() >= int64(sqlcipher.SaltSize) {
			hdr := make([]byte, sqlcipher.SaltSize)
			if _, e := f.ReadAt(hdr, 0); e != nil {
				o.mu.Unlock()
				f.Close()
				return sqlite3.SQLITE_IOERR
			}
			o.salt = hdr
		} else if o.salt == nil {
			o.salt = make([]byte, sqlcipher.SaltSize)
			if _, e := rand.Read(o.salt); e != nil {
				o.mu.Unlock()
				f.Close()
				return sqlite3.SQLITE_IOERR
			}
		}
	}
	salt := o.salt
	o.mu.Unlock()

	if salt == nil { // WAL opened before main — SQLite never does this; fail closed.
		f.Close()
		return sqlite3.SQLITE_CANTOPEN
	}
	codec, err := sqlcipher.NewCodec(sqlcipher.RawKey(o.key), salt, sqlcipher.Params{PageSize: o.ps})
	if err != nil {
		f.Close()
		return sqlite3.SQLITE_CANTOPEN
	}

	state := &codecState{
		f:          f,
		codec:      codec,
		kind:       kind,
		ps:         o.ps,
		delOnClose: flags&sqlite3.SQLITE_OPEN_DELETEONCLOSE != 0,
		path:       name,
		vfs:        o,
	}
	cf := (*codecCFile)(unsafe.Pointer(pFile))
	cf.base.pMethods = uintptr(unsafe.Pointer(&codecio))
	cf.handle = addObject(state)
	if pOutFlags != 0 {
		*(*int32)(unsafe.Pointer(pOutFlags)) = flags
	}
	return sqlite3.SQLITE_OK
}

func state(pFile uintptr) *codecState {
	return getObject((*codecCFile)(unsafe.Pointer(pFile)).handle).(*codecState)
}

func goBytes(p uintptr, n int32) []byte {
	return (*libc.RawMem)(unsafe.Pointer(p))[:n:n]
}

// zeroReserve blanks the per-page reserve trailer so every page the engine sees has
// a deterministic (zero) reserve — the invariant WAL frame checksums depend on.
func zeroReserve(page []byte) {
	r := page[len(page)-sqlcipher.Reserve:]
	for i := range r {
		r[i] = 0
	}
}

func codecRead(tls *libc.TLS, pFile, zBuf uintptr, iAmt int32, iOfst sqlite_int64) int32 {
	s := state(pFile)
	out := goBytes(zBuf, iAmt)
	var err error
	var short bool
	if s.kind == kindMain {
		short, err = s.readMain(out, int64(iOfst))
	} else {
		short, err = s.readWAL(out, int64(iOfst))
	}
	if err != nil {
		return sqlite3.SQLITE_IOERR_READ
	}
	if short {
		return sqlite3.SQLITE_IOERR_SHORT_READ
	}
	return sqlite3.SQLITE_OK
}

// readMain decrypts the covering page(s) and copies the requested range out,
// zeroing each page's reserve. A read wholly past EOF returns zeros + short.
func (s *codecState) readMain(out []byte, off int64) (short bool, err error) {
	ps := int64(s.ps)
	got := 0
	for got < len(out) {
		pos := off + int64(got)
		pgno := uint32(pos/ps) + 1
		pageStart := int64(pgno-1) * ps
		raw := make([]byte, ps)
		n, _ := readAtFull(s.f, raw, pageStart)
		if n == 0 { // past EOF: zero-fill remainder, signal short read
			for i := got; i < len(out); i++ {
				out[i] = 0
			}
			return true, nil
		}
		if n < int(ps) {
			return false, fmt.Errorf("partial page %d (%d/%d bytes)", pgno, n, ps)
		}
		plain, derr := s.codec.Decrypt(pgno, raw)
		if derr != nil {
			return false, derr // wrong key / tamper -> fail closed
		}
		zeroReserve(plain)
		got += copy(out[got:], plain[pos-pageStart:])
	}
	return false, nil
}

// readWAL serves the 32-byte header and 24-byte frame headers verbatim and
// decrypts each frame's page image (pgno read from the frame header on disk).
func (s *codecState) readWAL(out []byte, off int64) (short bool, err error) {
	ps := int64(s.ps)
	frame := frameHdr + ps
	got := 0
	for got < len(out) {
		pos := off + int64(got)
		var seg []byte
		if pos < walHdr {
			end := min64(walHdr, off+int64(len(out)))
			seg = make([]byte, end-pos)
			n, _ := readAtFull(s.f, seg, pos)
			if n == 0 {
				for i := got; i < len(out); i++ {
					out[i] = 0
				}
				return true, nil
			}
			got += copy(out[got:], seg[:n])
			continue
		}
		rel := pos - walHdr
		fi := rel / frame
		inF := rel % frame
		frameStart := walHdr + fi*frame
		if inF < frameHdr { // frame header region — verbatim
			end := min64(frameStart+frameHdr, off+int64(len(out)))
			seg = make([]byte, end-pos)
			n, _ := readAtFull(s.f, seg, pos)
			if n == 0 {
				for i := got; i < len(out); i++ {
					out[i] = 0
				}
				return true, nil
			}
			got += copy(out[got:], seg[:n])
			continue
		}
		// page-image region: decrypt the whole page, copy the requested slice.
		pageStart := frameStart + frameHdr
		var fh [4]byte
		if _, e := s.f.ReadAt(fh[:], frameStart); e != nil {
			return false, e
		}
		pgno := uint32(fh[0])<<24 | uint32(fh[1])<<16 | uint32(fh[2])<<8 | uint32(fh[3])
		raw := make([]byte, ps)
		n, _ := readAtFull(s.f, raw, pageStart)
		if n == 0 {
			for i := got; i < len(out); i++ {
				out[i] = 0
			}
			return true, nil
		}
		if n < int(ps) {
			return false, fmt.Errorf("partial wal page frame %d", fi)
		}
		plain, derr := s.codec.Decrypt(pgno, raw)
		if derr != nil {
			return false, derr
		}
		zeroReserve(plain)
		got += copy(out[got:], plain[pos-pageStart:])
	}
	return false, nil
}

func codecWrite(tls *libc.TLS, pFile, zBuf uintptr, iAmt int32, iOfst sqlite_int64) int32 {
	s := state(pFile)
	in := goBytes(zBuf, iAmt)
	var err error
	if s.kind == kindMain {
		err = s.writeMain(in, int64(iOfst))
	} else {
		err = s.writeWAL(in, int64(iOfst))
	}
	if err != nil {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	return sqlite3.SQLITE_OK
}

// writeMain encrypts each full page and writes the ciphertext at the same offset
// (on-disk size == logical size, 1 page ⇄ 1 page). Non-page-aligned writes get a
// read-modify-write, though the pager only ever writes whole pages here.
func (s *codecState) writeMain(in []byte, off int64) error {
	ps := int64(s.ps)
	done := 0
	for done < len(in) {
		pos := off + int64(done)
		pgno := uint32(pos/ps) + 1
		pageStart := int64(pgno-1) * ps
		inPageOff := pos - pageStart
		nWrite := int(ps - inPageOff)
		if done+nWrite > len(in) {
			nWrite = len(in) - done
		}
		var page []byte
		if inPageOff == 0 && nWrite == int(ps) {
			page = in[done : done+nWrite]
		} else { // partial: read-modify-write under the codec
			page = make([]byte, ps)
			if n, _ := readAtFull(s.f, page, pageStart); n == int(ps) {
				pt, err := s.codec.Decrypt(pgno, page)
				if err != nil {
					return err
				}
				page = pt
			}
			copy(page[inPageOff:], in[done:done+nWrite])
		}
		ct, err := s.codec.Encrypt(pgno, page)
		if err != nil {
			return err
		}
		if _, err := s.f.WriteAt(ct, pageStart); err != nil {
			return err
		}
		done += nWrite
	}
	return nil
}

// writeWAL writes the header and frame headers verbatim and encrypts each page
// image (pgno from the frame header, from the buffer if covered else from disk).
func (s *codecState) writeWAL(in []byte, off int64) error {
	ps := int64(s.ps)
	frame := frameHdr + ps
	done := 0
	for done < len(in) {
		pos := off + int64(done)
		if pos < walHdr {
			end := min64(walHdr, off+int64(len(in)))
			n := int(end - pos)
			if _, err := s.f.WriteAt(in[done:done+n], pos); err != nil {
				return err
			}
			done += n
			continue
		}
		rel := pos - walHdr
		fi := rel / frame
		inF := rel % frame
		frameStart := walHdr + fi*frame
		if inF < frameHdr {
			end := min64(frameStart+frameHdr, off+int64(len(in)))
			n := int(end - pos)
			if _, err := s.f.WriteAt(in[done:done+n], pos); err != nil {
				return err
			}
			done += n
			continue
		}
		// page-image region: must be a whole page starting at the image boundary.
		pageStart := frameStart + frameHdr
		if pos != pageStart || len(in)-done < int(ps) {
			return fmt.Errorf("sqlcipher/vfs: unaligned wal page write off=%d amt=%d", pos, len(in)-done)
		}
		pgno, err := s.walFramePgno(in, done, frameStart)
		if err != nil {
			return err
		}
		ct, err := s.codec.Encrypt(pgno, in[done:done+int(ps)])
		if err != nil {
			return err
		}
		if _, err := s.f.WriteAt(ct, pageStart); err != nil {
			return err
		}
		done += int(ps)
	}
	return nil
}

// walFramePgno reads the frame's big-endian page number, from the write buffer if
// this write covers the frame header, otherwise from the header already on disk
// (wal.c writes the header in a separate xWrite immediately before the page).
func (s *codecState) walFramePgno(in []byte, done int, frameStart int64) (uint32, error) {
	var fh [4]byte
	if done >= frameHdr { // header sits just before the page image in this buffer
		copy(fh[:], in[done-frameHdr:done-frameHdr+4])
	} else if _, err := s.f.ReadAt(fh[:], frameStart); err != nil {
		return 0, err
	}
	return uint32(fh[0])<<24 | uint32(fh[1])<<16 | uint32(fh[2])<<8 | uint32(fh[3]), nil
}

func codecTruncate(tls *libc.TLS, pFile uintptr, size sqlite_int64) int32 {
	if err := state(pFile).f.Truncate(int64(size)); err != nil {
		return sqlite3.SQLITE_IOERR_TRUNCATE
	}
	return sqlite3.SQLITE_OK
}

func codecSync(tls *libc.TLS, pFile uintptr, flags int32) int32 {
	if err := state(pFile).f.Sync(); err != nil {
		return sqlite3.SQLITE_IOERR_FSYNC
	}
	return sqlite3.SQLITE_OK
}

func codecFileSize(tls *libc.TLS, pFile, pSize uintptr) int32 {
	st, err := state(pFile).f.Stat()
	if err != nil {
		return sqlite3.SQLITE_IOERR_FSTAT
	}
	*(*sqlite_int64)(unsafe.Pointer(pSize)) = st.Size()
	return sqlite3.SQLITE_OK
}

func codecClose(tls *libc.TLS, pFile uintptr) int32 {
	cf := (*codecCFile)(unsafe.Pointer(pFile))
	s := getObject(cf.handle).(*codecState)
	s.f.Close()
	if s.delOnClose {
		os.Remove(s.path)
	}
	removeObject(cf.handle)
	return sqlite3.SQLITE_OK
}

func codecSectorSize(tls *libc.TLS, pFile uintptr) int32 { return 4096 }

func codecDeviceCharacteristics(tls *libc.TLS, pFile uintptr) int32 { return 0 }

// codecShmMap returns region iRegion of this database's wal-index, allocating and
// zeroing it on demand (SQLite requires a zeroed region on first map). bExtend==0
// means "don't create it" — return a null pointer, which SQLite treats as
// not-yet-present.
func codecShmMap(tls *libc.TLS, pFile uintptr, iRegion, szRegion, bExtend int32, pp uintptr) int32 {
	sh := &state(pFile).vfs.shm
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.szRegion = szRegion
	for int32(len(sh.regions)) <= iRegion {
		if bExtend == 0 {
			*(*uintptr)(unsafe.Pointer(pp)) = 0
			return sqlite3.SQLITE_OK
		}
		p := libc.Xmalloc(tls, libc.Tsize_t(szRegion))
		if p == 0 {
			return sqlite3.SQLITE_IOERR_NOMEM
		}
		z := (*libc.RawMem)(unsafe.Pointer(p))[:szRegion:szRegion]
		for i := range z {
			z[i] = 0
		}
		sh.regions = append(sh.regions, p)
	}
	*(*uintptr)(unsafe.Pointer(pp)) = sh.regions[iRegion]
	return sqlite3.SQLITE_OK
}

// codecShmLock is a no-op: the keyed store is single-writer (MaxOpenConns(1)), so
// the one connection is the only agent touching the wal-index and there is no
// cross-connection coordination to enforce.
func codecShmLock(tls *libc.TLS, pFile uintptr, offset, n, flags int32) int32 {
	return sqlite3.SQLITE_OK
}

// codecShmBarrier is a no-op: a single goroutine drives the connection, so there
// is no memory ordering to publish across CPUs.
func codecShmBarrier(tls *libc.TLS, pFile uintptr) {}

// codecShmUnmap frees the wal-index. SQLite rebuilds it from the -wal file on the
// next map, so releasing it here loses nothing.
func codecShmUnmap(tls *libc.TLS, pFile uintptr, deleteFlag int32) int32 {
	sh := &state(pFile).vfs.shm
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for _, p := range sh.regions {
		libc.Xfree(tls, p)
	}
	sh.regions = nil
	return sqlite3.SQLITE_OK
}

func codecDelete(tls *libc.TLS, pVfs, zPath uintptr, dirSync int32) int32 {
	if err := os.Remove(libc.GoString(zPath)); err != nil && !os.IsNotExist(err) {
		return sqlite3.SQLITE_IOERR_DELETE
	}
	return sqlite3.SQLITE_OK
}

func codecAccess(tls *libc.TLS, pVfs, zPath uintptr, flags int32, pResOut uintptr) int32 {
	res := int32(0)
	if _, err := os.Stat(libc.GoString(zPath)); err == nil {
		res = 1
	}
	*(*int32)(unsafe.Pointer(pResOut)) = res
	return sqlite3.SQLITE_OK
}

// readAtFull reads len(b) bytes at off, tolerating a short tail at EOF; it returns
// the number of bytes actually read (0 when off is at/after EOF).
func readAtFull(f *os.File, b []byte, off int64) (int, error) {
	n := 0
	for n < len(b) {
		m, err := f.ReadAt(b[n:], off+int64(n))
		n += m
		if err != nil {
			return n, nil // treat EOF/short as a short read; caller decides
		}
	}
	return n, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
