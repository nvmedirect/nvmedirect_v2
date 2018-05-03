/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "filemgr.h"
#include "filemgr_ops.h"
#include <sys/param.h>
static uint32_t crc322_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t
crc322(uint32_t crc, const void *buf, size_t size)
{
	const uint8_t *p;

	p = (uint8_t *)buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc322_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

#if !defined(WIN32) && !defined(_WIN32)

int _filemgr_linux_open(const char *pathname, int flags, mode_t mode)
{
    int fd;
    do {
        fd = open(pathname, flags | O_LARGEFILE, mode);
    } while (fd == -1 && errno == EINTR);

    if (fd < 0) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_OPEN_FAIL);
    }
    return fd;
}

ssize_t _filemgr_linux_pwrite(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pwrite(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                     FDB_RESULT_WRITE_FAIL);
    }
	//fprintf(stderr, "W %lu %lu %x\n", offset, count, crc322(-1, buf, 4096));
    return rv;
}

ssize_t _filemgr_linux_pread(int fd, void *buf, size_t count, cs_off_t offset)
{
    ssize_t rv;
    do {
        rv = pread(fd, buf, count, offset);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv < 0) {
        return (ssize_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                     FDB_RESULT_READ_FAIL);
    }
	//fprintf(stderr, "R %lu %lu %x\n", offset, count, crc322(-1, buf, 4096));
    return rv;
}

int _filemgr_linux_close(int fd)
{
    int rv = 0;
    if (fd != -1) {
        do {
            rv = close(fd);
        } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE
    }

    if (rv < 0) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_CLOSE_FAIL);
    }

    return FDB_RESULT_SUCCESS;
}

cs_off_t _filemgr_linux_goto_eof(int fd)
{
    cs_off_t rv = lseek(fd, 0, SEEK_END);
    if (rv < 0) {
        return (cs_off_t) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                      FDB_RESULT_SEEK_FAIL);
    }
    return rv;
}

// LCOV_EXCL_START
cs_off_t _filemgr_linux_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == -1) {
        return (cs_off_t) convert_errno_to_fdb_status(errno,
                                                      FDB_RESULT_READ_FAIL);
    }
    return st.st_size;
}
// LCOV_EXCL_STOP

int _filemgr_linux_fsync(int fd)
{
    int rv;
    do {
        rv = fsync(fd);
    } while (rv == -1 && errno == EINTR); // LCOV_EXCL_LINE

    if (rv == -1) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_FSYNC_FAIL);
    }

    return FDB_RESULT_SUCCESS;
}

// LCOV_EXCL_START
int _filemgr_linux_fdatasync(int fd)
{
#if defined(__linux__) && !defined(__ANDROID__)
    int rv;
    do {
        rv = fdatasync(fd);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        return (int) convert_errno_to_fdb_status(errno, // LCOV_EXCL_LINE
                                                 FDB_RESULT_FSYNC_FAIL);
    }

    return FDB_RESULT_SUCCESS;
#else // __linux__ && not __ANDROID__
    return _filemgr_linux_fsync(fd);
#endif // __linux__ && not __ANDROID__
}
// LCOV_EXCL_STOP

void _filemgr_linux_get_errno_str(char *buf, size_t size) {
    if (!buf) {
        return;
    } else {
        char *tbuf = alca(char, size);
#ifdef _POSIX_SOURCE
        char *ret = strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, ret);
#else
        (void)strerror_r(errno, tbuf, size);
        snprintf(buf, size, "errno = %d: '%s'", errno, tbuf);
#endif
    }
}

int _filemgr_aio_init(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    if (!aio_handle->queue_depth || aio_handle->queue_depth > 512) {
        aio_handle->queue_depth =  ASYNC_IO_QUEUE_DEPTH;
    }
    if (!aio_handle->block_size) {
        aio_handle->block_size = FDB_BLOCKSIZE;
    }

    void *buf;
    malloc_align(buf, FDB_SECTOR_SIZE,
                 aio_handle->block_size * aio_handle->queue_depth);
    aio_handle->aio_buf = (uint8_t *) buf;
    aio_handle->offset_array = (uint64_t*)
        malloc(sizeof(uint64_t) * aio_handle->queue_depth);

    aio_handle->ioq = (struct iocb**)
        malloc(sizeof(struct iocb*) * aio_handle->queue_depth);
    aio_handle->events = (struct io_event *)
        calloc(aio_handle->queue_depth, sizeof(struct io_event));

    for (size_t k = 0; k < aio_handle->queue_depth; ++k) {
        aio_handle->ioq[k] = (struct iocb*) malloc(sizeof(struct iocb));
    }
    memset(&aio_handle->ioctx, 0, sizeof(io_context_t));

    int rc = io_queue_init(aio_handle->queue_depth, &aio_handle->ioctx);
    if (rc < 0) {
        return FDB_RESULT_AIO_INIT_FAIL;
    }
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_prep_read(struct async_io_handle *aio_handle, size_t aio_idx,
                           size_t read_size, uint64_t offset)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    io_prep_pread(aio_handle->ioq[aio_idx], aio_handle->fd,
                  aio_handle->aio_buf + (aio_idx * aio_handle->block_size),
                  aio_handle->block_size,
                  (offset / aio_handle->block_size) * aio_handle->block_size);
    // Record the original offset.
    aio_handle->offset_array[aio_idx] = offset;
    aio_handle->ioq[aio_idx]->data = &aio_handle->offset_array[aio_idx];
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_submit(struct async_io_handle *aio_handle, int num_subs)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }
    int rc = io_submit(aio_handle->ioctx, num_subs, aio_handle->ioq);
    if (rc < 0) {
        return FDB_RESULT_AIO_SUBMIT_FAIL;
    }
    return rc; // 'rc' should be equal to 'num_subs' upon succcess.
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_getevents(struct async_io_handle *aio_handle, int min,
                           int max, unsigned int timeout)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    // Passing max timeout (ms) means that it waits until at least 'min' events
    // have been seen.
    bool wait_for_min = true;
    struct timespec ts;
    if (timeout < (unsigned int) -1) {
        ts.tv_sec = timeout / 1000;
        timeout %= 1000;
        ts.tv_nsec = timeout * 1000000;
        wait_for_min = false;
    }

    int num_events = io_getevents(aio_handle->ioctx, min, max, aio_handle->events,
                                  wait_for_min ? NULL : &ts);
    if (num_events < 0) {
        return FDB_RESULT_AIO_GETEVENTS_FAIL;
    }
    return num_events;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

int _filemgr_aio_destroy(struct async_io_handle *aio_handle)
{
#ifdef _ASYNC_IO
    if (!aio_handle) {
        return FDB_RESULT_INVALID_ARGS;
    }

    io_queue_release(aio_handle->ioctx);
    for(size_t k = 0; k < aio_handle->queue_depth; ++k)
    {
        free(aio_handle->ioq[k]);
    }
    free(aio_handle->ioq);
    free(aio_handle->events);
    free_align(aio_handle->aio_buf);
    free(aio_handle->offset_array);
    return FDB_RESULT_SUCCESS;
#else
    return FDB_RESULT_AIO_NOT_SUPPORTED;
#endif
}

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/mount.h>
#elif !defined(__sun)
#include <sys/vfs.h>
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC 0x9123683E
#endif

#ifdef HAVE_BTRFS_IOCTL_H
#include <btrfs/ioctl.h>
#else
#include <sys/ioctl.h>
#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif //BTRFS_IOCTL_MAGIC

struct btrfs_ioctl_clone_range_args {
    int64_t src_fd;
    uint64_t src_offset;
    uint64_t src_length;
    uint64_t dest_offset;
};

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC
#define _IOC(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
        ((type) << _IOC_TYPESHIFT) | \
        ((nr)   << _IOC_NRSHIFT) | \
        ((size) << _IOC_SIZESHIFT))
#endif // _IOC

#define _IOC_TYPECHECK(t) (sizeof(t))
#ifndef _IOW
#define _IOW(type,nr,size) _IOC(_IOC_WRITE,(type),(nr),\
                          (_IOC_TYPECHECK(size)))
#endif //_IOW

#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, \
                              struct btrfs_ioctl_clone_range_args)
#endif // HAVE_BTRFS_IOCTL_H

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC 0xEF53
#endif

#ifndef EXT4_IOC_TRANFER_BLK_OWNERSHIP
/* linux/fs/ext4/ext4.h */
#define EXT4_IOC_TRANFER_BLK_OWNERSHIP  _IOWR('f', 22, struct tranfer_blk_ownership)

struct tranfer_blk_ownership {
    int32_t dest_fd;           /* destination file decriptor */
    uint64_t src_start;        /* logical start offset in block for src */
    uint64_t dest_start;       /* logical start offset in block for dest */
    uint64_t len;              /* block length to be onwership-transfered */
};
#endif // EXT4_IOC_TRANSFER_BLK_OWNERSHIP

#ifndef __sun
static
int _filemgr_linux_ext4_share_blks(int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int err;
    struct tranfer_blk_ownership tbo;
    tbo.dest_fd = dst_fd;
    tbo.src_start = src_off;
    tbo.dest_start = dst_off;
    tbo.len = len;
    err = ioctl(src_fd, EXT4_IOC_TRANFER_BLK_OWNERSHIP, &tbo);
    if (err) {
        return errno;
    }
    return err;
}
#endif

int _filemgr_linux_get_fs_type(int src_fd)
{
#ifdef __sun
    // No support for ZFS
    return FILEMGR_FS_NO_COW;
#else
    int ret;
    struct statfs sfs;
    ret = fstatfs(src_fd, &sfs);
    if (ret != 0) {
        return FDB_RESULT_INVALID_ARGS;
    }
    switch (sfs.f_type) {
        case EXT4_SUPER_MAGIC:
            ret = _filemgr_linux_ext4_share_blks(src_fd, src_fd, 0, 0, 0);
            if (ret == 0) {
                ret = FILEMGR_FS_EXT4_WITH_COW;
            } else {
                ret = FILEMGR_FS_NO_COW;
            }
            break;
        case BTRFS_SUPER_MAGIC:
            ret = FILEMGR_FS_BTRFS;
            break;
        default:
            ret = FILEMGR_FS_NO_COW;
    }
    return ret;
#endif
}

int _filemgr_linux_copy_file_range(int fs_type,
                                   int src_fd, int dst_fd, uint64_t src_off,
                                   uint64_t dst_off, uint64_t len)
{
    int ret = (int)FDB_RESULT_INVALID_ARGS;
#ifndef __sun
    if (fs_type == FILEMGR_FS_BTRFS) {
        struct btrfs_ioctl_clone_range_args cr_args;

        memset(&cr_args, 0, sizeof(cr_args));
        cr_args.src_fd = src_fd;
        cr_args.src_offset = src_off;
        cr_args.src_length = len;
        cr_args.dest_offset = dst_off;
        ret = ioctl(dst_fd, BTRFS_IOC_CLONE_RANGE, &cr_args);
        if (ret != 0) { // LCOV_EXCL_START
            ret = errno;
        }              // LCOV_EXCL_STOP
    } else if (fs_type == FILEMGR_FS_EXT4_WITH_COW) {
        ret = _filemgr_linux_ext4_share_blks(src_fd, dst_fd, src_off,
                                             dst_off, len);
    }
#endif
    return ret;
}

struct filemgr_ops linux_ops = {
    _filemgr_linux_open,
    _filemgr_linux_pwrite,
    _filemgr_linux_pread,
    _filemgr_linux_close,
    _filemgr_linux_goto_eof,
    _filemgr_linux_file_size,
    _filemgr_linux_fdatasync,
    _filemgr_linux_fsync,
    _filemgr_linux_get_errno_str,
    // Async I/O operations
    _filemgr_aio_init,
    _filemgr_aio_prep_read,
    _filemgr_aio_submit,
    _filemgr_aio_getevents,
    _filemgr_aio_destroy,
    _filemgr_linux_get_fs_type,
    _filemgr_linux_copy_file_range
};

struct filemgr_ops * get_linux_filemgr_ops()
{
    return &linux_ops;
}

#endif
