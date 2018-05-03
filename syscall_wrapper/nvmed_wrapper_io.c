#include "nvmed_wrapper.h"
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define WRAPFS_DEBUG 1

#if WRAPFS_DEBUG
#define WRAPFS_OPS_DEBUG 0
#define ONLY_WRAPFS_OPS_DEBUG 1
#define WRAPFS_PATH_DEBUG 0

#define NVMED_WRAP_DBG(fmt, args...) fprintf(stderr, fmt, ##args) 
#endif

/////
bool isUsrFSPath(const char *path, char** path_ptr, char* abs_path) {
	size_t path_len;
	static int need_init = 1;
	struct fs_init_opt fs_opt;

	realpath(path, abs_path);
	path_len = strlen(abs_path);

	if(path_len > USR_ABS_DIR_LEN &&
			abs_path[USR_ABS_DIR_LEN] != '/') {
		*path_ptr = (char *)path;
		return false;
	}
	if(!strncmp(USR_ABS_DIR, abs_path, USR_ABS_DIR_LEN)) {
		if(need_init) {
			fs_opt.path = USR_ABS_DIR;
			fs_opt.dev_path = "/dev/nvme0n1";
			fs_opt.meta_ratio = 12;

			if(req_format && fs_ops->format) {
				fs_ops->format(&fs_opt);
			}

			if(fs_ops->init) {
				fs_ops->init(&fs_opt);
			}
			need_init = 0;
		}
		
#if WRAPFS_PATH_DEBUG
		NVMED_WRAP_DBG("========================================\n");
		NVMED_WRAP_DBG("Input : (%lu) %s\n", strlen(path), path);
		NVMED_WRAP_DBG("ABS Path: (%lu) %s\n", strlen(abs_path), abs_path);
		//NVMED_WRAP_DBG("Xlat Path: (%lu) %s\n", strlen(abs_path + USR_ABS_DIR_LEN-1), abs_path + USR_ABS_DIR_LEN);
		
#endif
		
		if(path_len == USR_ABS_DIR_LEN) {
			strcpy(abs_path, "/");
		}
		else if(!strncmp(path, USR_DIR_PARENT, USR_DIR_PARENT_LEN)) {
			if(path[USR_DIR_PARENT_LEN] == '/' &&
					path[USR_DIR_PARENT_LEN+1] == '.' &&
					path[USR_DIR_PARENT_LEN+2] == '/')
				strcpy(abs_path, path + USR_DIR_PARENT_LEN+2);
			else
				strcpy(abs_path, path + USR_DIR_PARENT_LEN);
		}
		else if(!strncmp(path, USR_DIR, USR_DIR_LEN))
			strcpy(abs_path, path + (USR_DIR_LEN - 1));
		else
			strcpy(abs_path, abs_path + USR_ABS_DIR_LEN);

		*path_ptr = abs_path;

#if WRAPFS_PATH_DEBUG
		NVMED_WRAP_DBG("Return   : (%lu) %s\n", strlen(abs_path), abs_path);
		NVMED_WRAP_DBG("========================================\n");
#endif
		return true;
	}

	*path_ptr = (char *)path;
	return false;
}
/////
int creat(const char *pathname, mode_t mode) {
	printf("creat======================================================================\n");
	return 0;
}
int creat64(const char *pathname, mode_t mode) {
	printf("creat======================================================================\n");
	return 0;
}
int open64(const char *path, int flags, ...) {
	printf("open64======================================================================\n");
	
	return 0;
}
int open(const char *path, int flags, ...) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	int fd = 0;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	if(isUsrPath) {
		cur_ops = fs_ops;
		fd = cur_ops->open(new_path,flags);

		if(fd > 0) 
			fd+=USR_FD_START;
	}
	else
		fd = cur_ops->open(new_path,flags);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, new_path, fd);
#endif

	return fd;
}

ssize_t read(int fd, void *buf, size_t count) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	ssize_t ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->read(new_fd, buf, count);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %ld\n", __func__, fd, ret);
#endif

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	ssize_t ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->write(new_fd, buf, count);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %ld\n", __func__, fd, ret);
#endif

	return ret;
}

int close(int fd) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->close(new_fd);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

FILE *fopen64(const char *path, const char *mode) {
	char abs_path[PATH_MAX];
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	FILE* new_fp;

	if(isUsrPath) {
		new_fp = calloc(1, sizeof(FILE));
		new_fp->_fileno = open(path,00000100);
	}
	else {
		new_fp = orig_fopen64(path, mode);
	}

	return new_fp;
}

int fclose(FILE *fp) {
	int ret;

	if(fp->_fileno >= USR_FD_START) {
		ret = close(fp->_fileno);
		free(fp);
	}
	else {
		ret = orig_fclose(fp);
	}
	
	return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;

	if(stream->_fileno >= USR_FD_START) {
		ret = read(stream->_fileno, ptr, size * nmemb);
	}
	else {
		ret = orig_fread(ptr, size, nmemb, stream);
	}
	
	return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;

	if(stream->_fileno >= USR_FD_START) {
		ret = write(stream->_fileno, ptr, size * nmemb);
	}
	else {
		ret = orig_fwrite(ptr, size, nmemb, stream);
	}
	
	return ret;
}

int __xstat64(int ver, const char *path, struct stat64 *stat_buf) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}
	ret = cur_ops->__xstat64(ver, new_path, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s => %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int __xstat(int ver, const char *path, struct stat *stat_buf) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}
	ret = cur_ops->__xstat(ver, new_path, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(new_path)
#endif
		NVMED_WRAP_DBG("%s: %s => %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int __fxstat64(int ver, int fd, struct stat64 *stat_buf) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}
	ret = cur_ops->__fxstat64(ver, new_fd, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d => %d\n", __func__, fd, ret);
#endif

	return ret;
}

int __fxstat(int ver, int fd, struct stat *stat_buf) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}
	ret = cur_ops->__fxstat(ver, new_fd, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d => %d\n", __func__, fd, ret);
#endif

	return ret;
}
int __lxstat64(int ver, const char *path, struct stat64 *stat_buf) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->__lxstat64(ver, new_path, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s => %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int __lxstat(int ver, const char *path, struct stat *stat_buf) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->__lxstat(ver, new_path, stat_buf);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s => %d\n", __func__, new_path, ret);
#endif

	return ret;
}

off_t lseek(int fd, off_t offset, int whence) {
	off_t ret;
	struct fs_ops *cur_ops = &fs_ops_linux;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}
	ret = cur_ops->lseek(new_fd, offset, whence);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d => %ld\n", __func__, fd, ret);
#endif

	return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	ssize_t ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->pread(new_fd, buf, count, offset);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %ld\n", __func__, fd, ret);
#endif

	return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	ssize_t ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->pwrite(new_fd, buf, count, offset);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %ld\n", __func__, fd, ret);
#endif

	return ret;
}

int	fallocate(int fd, int mode, off_t offset, off_t len) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->fallocate(new_fd, mode, offset, len);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	access(const char *path, int mode) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->access(new_path, mode);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int	fcntl(int fd, int cmd, ... /* arg */ ) {
	va_list ap;
	void *args;
	int ret;
	struct fs_ops *cur_ops = &fs_ops_linux;
	int new_fd = fd;

	va_start(ap, cmd);
	args = va_arg(ap, void *);
	va_end(ap);

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->fcntl(new_fd, cmd, args); 

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	flock(int fd, int operation) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int new_fd = fd;
	int ret;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->flock(new_fd, operation);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	fsync(int fd) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}
	
	ret = cur_ops->fsync(new_fd);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	fdatasync(int fd) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->fdatasync(new_fd);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	truncate(const char *path, off_t length) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->truncate(new_path, length);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int	ftruncate(int fd, off_t length) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}
	
	ret = cur_ops->ftruncate(new_fd, length);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %d -> %d\n", __func__, fd, ret);
#endif

	return ret;
}

int	rename(const char *oldpath, const char *newpath) {
	char new_abs_path[PATH_MAX];
	char old_abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath_new = isUsrFSPath(newpath, &new_path, new_abs_path);
	char* old_path;
	bool isUsrPath_old = isUsrFSPath(oldpath, &old_path, old_abs_path);
	int ret;

	if(isUsrPath_new && isUsrPath_old) 
		cur_ops = fs_ops;
	else if(isUsrPath_new != isUsrPath_old) {
		fprintf(stderr, "****************************************************\n");
		fprintf(stderr, "* ERROR!!!!!                                       *\n");
		fprintf(stderr, "* Rename inter FS not support                      *\n");
		fprintf(stderr, "****************************************************\n");
		return -1;
	}

	ret = cur_ops->rename(old_path, new_path);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath_new && isUsrPath_old) 
#endif
		NVMED_WRAP_DBG("%s: %s -> %s -> %d\n", __func__, old_path, new_path, ret);
#endif

	return ret;
}

int	mkdir(const char *path, mode_t mode) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(path, &new_path, abs_path);
	int ret;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->mkdir(new_path, mode);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int	rmdir(const char *pathname) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(pathname, &new_path, abs_path);
	int ret;
	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->rmdir(new_path);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, new_path, ret);
#endif

	return ret;
}

int sync(void) {
	int ret;
	struct fs_ops *def_ops = &fs_ops_linux;

	if(fs_ops != def_ops) {
		ret = fs_ops->sync();
#if WRAPFS_OPS_DEBUG
		NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, fs_ops->fs_name, ret);
#endif
	}

	ret = def_ops->sync();

#if WRAPFS_OPS_DEBUG && !ONLY_WRAPFS_OPS_DEBUG
	NVMED_WRAP_DBG("%s: %s -> %d\n", __func__, def_ops->fs_name, ret);
#endif

	return ret;
}

int syncfs(int fd) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	int new_fd = fd;

	if(fd >= USR_FD_START) {
		new_fd -= USR_FD_START;
		cur_ops = fs_ops;
	}

	ret = cur_ops->syncfs(new_fd);
#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(fd >= USR_FD_START)
#endif
		NVMED_WRAP_DBG("%s: %s(fd:%d) -> %d\n", __func__, cur_ops->fs_name, fd, ret);
#endif

	return ret;
}

DIR *opendir(const char *name) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	char* new_path;
	bool isUsrPath = isUsrFSPath(name, &new_path, abs_path);
	DIR* ret;
	int i;
	bool entryFound = false;

	if(isUsrPath) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->opendir(new_path);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(isUsrPath)
#endif
		NVMED_WRAP_DBG("%s: %s -> %p\n", __func__, new_path, ret);
#endif

	if(isUsrPath) {
		pthread_spin_lock(&dirp_list_lock);
		for(i=0; i<nr_dirp_list; i++) {
			if(dirp_list[i] == NULL) {
				dirp_list[i] = ret;
				entryFound = true;
				break;
			}
		}
		if(!entryFound)
			fprintf(stderr, "%s: DIRP entry full\n", __func__);
		pthread_spin_unlock(&dirp_list_lock);
	}

	return ret;
}

struct dirent *readdir(DIR *dirp) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	struct dirent *ret;
	bool entryFound = false;
	int i;

	pthread_spin_lock(&dirp_list_lock);
	for(i=0; i<nr_dirp_list; i++) {
		if(dirp_list[i] == dirp) {
			entryFound = true;
			break;
		}
	}
	pthread_spin_unlock(&dirp_list_lock);

	if(entryFound)
		cur_ops = fs_ops;

	ret = cur_ops->readdir(dirp);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(entryFound)
#endif
		NVMED_WRAP_DBG("%s: %p -> %p\n", __func__,dirp, ret);
#endif

	return ret;
}

int readdir64_r (DIR *__restrict __dirp,
		            struct dirent64 *__restrict __entry,
					            struct dirent64 **__restrict __result) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	bool entryFound = false;
	int i;
	int ret;

	pthread_spin_lock(&dirp_list_lock);
	for(i=0; i<nr_dirp_list; i++) {
		if(dirp_list[i] == __dirp) {
			entryFound = true;
			break;
		}
	}
	pthread_spin_unlock(&dirp_list_lock);

	if(entryFound) {
		cur_ops = fs_ops;
	}

	ret = cur_ops->readdir64_r(__dirp, __entry, __result);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(entryFound)
#endif
		NVMED_WRAP_DBG("%s(%s-%d): %p -> %p, %p = %d\n", __func__, __entry->d_name, __entry->d_reclen, __dirp, __entry, *__result, ret);
#endif

	return ret;
}

int closedir(DIR *dirp) {
	struct fs_ops *cur_ops = &fs_ops_linux;
	int ret;
	bool entryFound = false;
	int i;

	pthread_spin_lock(&dirp_list_lock);
	for(i=0; i<nr_dirp_list; i++) {
		if(dirp_list[i] == dirp) {
			dirp_list[i] = NULL;
			entryFound = true;
			break;
		}
	}
	pthread_spin_unlock(&dirp_list_lock);

	if(entryFound)
		cur_ops = fs_ops;

	ret = cur_ops->closedir(dirp);

#if WRAPFS_OPS_DEBUG
#if ONLY_WRAPFS_OPS_DEBUG
	if(entryFound)
#endif
		NVMED_WRAP_DBG("%s: %p -> %d\n", __func__,dirp, ret);
#endif

	return ret;
}

#if 0
int	openat(int dirfd, const char *pathname, int flags, ...) {
	char abs_path[PATH_MAX];
	struct fs_ops *cur_ops = &fs_ops_linux;
	fprintf(stderr, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX %s\n", __func__);

	return 0;
}
int	getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
	fprintf(stderr, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX %s\n", __func__);

	return 0;
}
#endif
