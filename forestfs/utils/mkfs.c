#include <stdio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include "../library/lib_ffs.h"

void usage(char* path) {
	printf("Usage : %s [FFS File or Blkdev] (Size in GiB)\n", path);
}

int main(int argc, char** argv) {
	char* path;
	struct stat root_stat;
	FFS_FORMAT_CONFIG format_config;
	FFS_INIT_CONFIG init_config;

	uint64_t file_size_in_bytes;
	int ret;
	int fd;

	if(argc < 2) {
		usage(argv[0]);
		return -1;
	}

	path = argv[1];

	ret = lstat(path, &root_stat);
	if(ret < 0) return FFS_RESULT_FAIL;

	// FILE SIZE Check
	if(argc == 3) {
		format_config.fs_size = atoi(argv[2]) * 1024 * 1024 * 1024;
	}
	else if(S_ISREG(root_stat.st_mode)) {
		format_config.fs_size = root_stat.st_size;
	}
	else if(S_ISBLK(root_stat.st_mode)) {
		fd = open(path, O_RDONLY);
		ret = ioctl(fd, BLKGETSIZE64, &file_size_in_bytes);
		if(ret < 0) perror("Error\n");
		format_config.fs_size = file_size_in_bytes;
		close(fd);
	}

	format_config.meta_ratio = 12;
	ffs_format(path, &format_config);

	init_config.storage_engine = LINUX;
	ffs_init(path, &init_config);
	ffs_mkdir("/", 0);
	ffs_mkdir("/tmp", 0);
	ffs_finalize();

	return FFS_RESULT_SUCCESS;
}
