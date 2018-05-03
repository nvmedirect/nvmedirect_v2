#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <dirent.h>
#include <libforestdb/forestdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <lib_nvmed.h>

#include <nvmed_wrapper.h>

#include "utils/radix-tree.h"
#include "lib_ffs.h"

#define FFS_DEBUG 1

#define FFS_STR_HELPER(x) #x
#define FFS_STR(x) FFS_STR_HELPER(x)

#define FFS_META "FFS_META"

#define ffs_set_sb(handle, buf) \
	ffs_fdb_set_kv(handle, "FFS_SB", 6, buf, sizeof(*buf));
#define ffs_get_sb(handle, data_buf, sz_buf) \
	ffs_fdb_get_kv(handle, "FFS_SB", 6, (void **)&data_buf, (void *)sz_buf);

#define ffs_set_inode(handle, pathname, buf) \
	ffs_fdb_set_kv(handle, pathname, strlen(pathname), buf, sizeof(*buf));
#define ffs_get_inode(handle, pathname, data_buf, sz_buf) \
	ffs_fdb_get_kv(handle, pathname, strlen(pathname), (void **)&data_buf, (void *)sz_buf);
#define ffs_del_inode(handle, pathname) \
	ffs_fdb_del_kv(handle, pathname, strlen(pathname));

#define FD_TO_INODE(fd) (ffs_fd_array+fd)->ffs_inode

#define FFS_META_FLUSH(handle) ffs_fdb_commit(handle, FDB_COMMIT_NORMAL)
#define FFS_META_FLUSH_WAL(handle) ffs_fdb_commit(handle, FDB_COMMIT_MANUAL_WAL_FLUSH)

struct io_ops *io_ops = NULL;

FFS_ROOT* ffs_root;
FFS_FD_INFO* ffs_fd_array;

fdb_status ffs_fdb_commit(fdb_file_handle *handle, int type) {
	fdb_status status;
	while(true) {
		status = fdb_commit(handle, type);
		if(status != FDB_RESULT_HANDLE_BUSY)
			break;
	}
	assert(status == FDB_RESULT_SUCCESS);

	return status;
}

fdb_status ffs_fdb_get_kv(fdb_kvs_handle *handle,
		const void *key, size_t keylen,
		void **value_out, size_t *valuelen_out) {
	fdb_status status;
	while(true) {
		status = fdb_get_kv(handle, key, keylen, value_out, valuelen_out);
		if(status != FDB_RESULT_HANDLE_BUSY)
			break;
	}

	return status;
}

fdb_status ffs_fdb_set_kv(fdb_kvs_handle *handle,
		const void *key, size_t keylen,
		const void *value, size_t valuelen) {
	fdb_status status;
	while(true) {
		status = fdb_set_kv(handle, key, keylen, value, valuelen);
		if(status != FDB_RESULT_HANDLE_BUSY)
			break;
	}

	return status;
}

fdb_status ffs_fdb_del_kv(fdb_kvs_handle *handle,
		const void *key, size_t keylen) {
	fdb_status status;
	while(true) {
		status = fdb_del_kv(handle, key, keylen);
		if(status != FDB_RESULT_HANDLE_BUSY)
			break;
	}

	return status;
}

fdb_status ffs_set_bmap(fdb_kvs_handle* kvhandle, uint32_t idx, void* buf) {
	char keyname[32];
	sprintf(keyname, "FFS_BMAP_%u", idx);

	return ffs_fdb_set_kv(kvhandle, keyname, strlen(keyname), buf, FDB_DATA_IN_BLK);
}

fdb_status ffs_get_bmap(fdb_kvs_handle* kvhandle, uint32_t idx, void** buf, ssize_t* sz_buf) {
	char keyname[32];
	sprintf(keyname, "FFS_BMAP_%u", idx);

	return ffs_fdb_get_kv(kvhandle, keyname, strlen(keyname), buf, (void *)sz_buf);
}


ssize_t __io_read(FFS_FD fd, void* buf, size_t count, off_t offset) {
	ssize_t ret;
	FFS_FD_INFO* fd_info;

	fd_info = ffs_fd_array + fd;

	if(ffs_root->storage_engine == LINUX)
		ret = pread(ffs_root->fd, buf, count, offset);
	else if(ffs_root->storage_engine == NVMeDirect) {
		if((fd_info->flags & O_SYNC) == O_SYNC)
			ret = nvmed_pread(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_SYNC],
				buf, count, offset);
		else
			ret = nvmed_pread(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC],
				buf, count, offset);
	}
	else 
		ret = 0;

	return ret;
}

ssize_t __io_write(FFS_FD fd, void* buf, size_t count, off_t offset) {
	ssize_t ret;
	FFS_FD_INFO* fd_info;

	fd_info = ffs_fd_array + fd;

	if(ffs_root->storage_engine == LINUX)
		ret = pwrite(ffs_root->fd, buf, count, offset);
	else if(ffs_root->storage_engine == NVMeDirect) {
		if((fd_info->flags & O_SYNC) == O_SYNC)
			ret = nvmed_pwrite(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_SYNC],
				buf, count, offset);//, FD_TO_INODE(fd));
		else
			ret = nvmed_pwrite(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC],
				buf, count, offset);//, FD_TO_INODE(fd));
	}
	else 
		ret = 0;

	return ret;
}

ssize_t __io_discard(size_t count, off_t offset) {
	return count;
}

int __io_fsync(FFS_FD fd, bool isDataSync) {
	fdb_status status;

	if(isDataSync == false) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return FFS_RESULT_FAIL;
	}
	

	if(ffs_root->storage_engine == LINUX)
		return fdatasync(ffs_root->fd);
	else
		return 0;
	//nvmed_flush_private(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC], FD_TO_INODE(fd));
}

int __io_sync() {
	int ret = 0;

	if(ffs_root->storage_engine == LINUX)
		sync();
	else if(ffs_root->storage_engine == NVMeDirect)
		ret = nvmed_flush(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC]);

	return ret;
}

/*
 * find the position of the first 0 in a 8-bit array
 */
inline static unsigned short __find_first_zero(uint8_t bit_array)
{
	unsigned pos = 0;

	__asm__("bsfl %1,%0\n\t"
			"jne 1f\n\t"
			"movl $32, %0\n"
			"1:"
			: "=r" (pos)
			: "r" (~(bit_array)));

	if (pos > 7)
		return 8;

	return (unsigned short) pos;
}

//FFS_STATUS ffs_format(const char* path, FFS_FORMAT_CONFIG* config) {
static FFS_STATUS ffs_format(struct fs_init_opt *opt) {
	const char* path = opt->dev_path;
	fdb_file_handle *fhandle;
	fdb_kvs_handle *kvhandle;
	fdb_status status;
	fdb_config db_config;
	fdb_kvs_config kvs_config;
	int fd;

	struct stat root_stat;
	uint64_t file_size_in_bytes;
	uint8_t	bmap[FDB_DATA_IN_BLK];
	int idx, sub_idx, tmp, last_byte;
	int ret;
	FFS_FORMAT_CONFIG *config = calloc(1, sizeof(FFS_FORMAT_CONFIG));

	FFS_SB ffs_sb;
	FFS_SB* ffs_sb2;

	ret = lstat(path, &root_stat);
	if(ret < 0) return FFS_RESULT_FAIL;

	config->meta_ratio = opt->meta_ratio;

	// FILE SIZE Check
	if(S_ISREG(root_stat.st_mode)) {
		if(root_stat.st_size < config->fs_size)
			return FFS_RESULT_FAIL;
	}
	else if(S_ISBLK(root_stat.st_mode)) {
		fd = open(path, O_RDWR);
		ioctl(fd, BLKGETSIZE64, &file_size_in_bytes);
		close(fd);
		if(file_size_in_bytes < config->fs_size)
			return FFS_RESULT_FAIL;
		config->fs_size = file_size_in_bytes;
	}
	else 
		return FFS_RESULT_FAIL;

	// Forest DB CONFIG
	db_config = fdb_get_default_config();
	db_config.compaction_mode = FDB_COMPACTION_MANUAL;
	db_config.compaction_threshold = 0;
	db_config.block_reusing_threshold = 65;
	db_config.need_init = true;
	db_config.storage_engine = LINUX;
	// Open ForestDB
	kvs_config = fdb_get_default_kvs_config();
	status = fdb_open(&fhandle, path, &db_config);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = fdb_kvs_open(fhandle, &kvhandle, FFS_META, &kvs_config);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	// Calc Meta & Data size
	ffs_sb.num_fs_blocks = config->fs_size / FFS_BLK_SIZE;
	ffs_sb.num_meta_blocks = ffs_sb.num_fs_blocks * config->meta_ratio / 100;
	ffs_sb.num_data_blocks = ffs_sb.num_fs_blocks - ffs_sb.num_meta_blocks;
	ffs_sb.num_free_blocks = ffs_sb.num_data_blocks;
	ffs_sb.num_bmap_blocks = ffs_sb.num_data_blocks / (FDB_DATA_IN_BLK * 8);
	if(ffs_sb.num_data_blocks % (FDB_DATA_IN_BLK*8) > 0) ffs_sb.num_bmap_blocks++;

	// SET SB
	status = ffs_set_sb(kvhandle, &ffs_sb);
	assert(status == FDB_RESULT_SUCCESS);

	// INIT BITMAP
	for(idx=0; idx<ffs_sb.num_bmap_blocks; idx++) {
		memset(bmap, 0x0, FDB_DATA_IN_BLK);
		if(idx == ffs_sb.num_bmap_blocks - 1) {
			last_byte = ffs_sb.num_data_blocks % (FDB_DATA_IN_BLK*8);
			last_byte = (last_byte/8) + !!(last_byte%8);
			for(sub_idx=0; sub_idx < last_byte; sub_idx++) {
				bmap[sub_idx] = 0;
				if(sub_idx == last_byte-1) {
					for(tmp = ffs_sb.num_data_blocks % (FDB_DATA_IN_BLK*8) % 8;
						tmp < 8; tmp ++) {
						bmap[sub_idx] |= 1 << tmp;
					}
				}
			}
			for(sub_idx=last_byte; sub_idx < FDB_DATA_IN_BLK; sub_idx++)
				bmap[sub_idx] = -1;
		}
		status = ffs_set_bmap(kvhandle, idx, bmap);
	}

	status = FFS_META_FLUSH(fhandle);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = ffs_get_sb(kvhandle, ffs_sb2, &ret);
	assert(status == FDB_RESULT_SUCCESS);
	status = fdb_kvs_close(kvhandle);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = fdb_close(fhandle);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	return FFS_RESULT_SUCCESS;
}

//FFS_STATUS ffs_init(const char* path, FFS_INIT_CONFIG* config) {
static FFS_STATUS ffs_init(struct fs_init_opt *opt) {
	const char* path = opt->dev_path;
	FFS_SB* ffs_sb;
	fdb_status status;
	int i;
	int ret;
	NVMED* nvmed;
	NVMED_QUEUE* nvmed_queue;
	NVMED_HANDLE* nvmed_handle;

	FFS_INIT_CONFIG *config = calloc(1, sizeof(FFS_INIT_CONFIG));
	config->storage_engine = NVMeDirect;
	config->prealloc_blks = 4;
	if(config->storage_engine == LINUX) {
		//permission check
		ret = access(path, F_OK);
		if(ret != 0) return FFS_RESULT_FAIL;
	}
	else {
		nvmed = nvmed_open((char *)path, 0); //NVMED_NO_CACHE);
		if(nvmed == NULL) {
			return FFS_RESULT_FAIL;
		}
	}

	//open
	ffs_root = calloc(1, sizeof(FFS_ROOT));

	if(config->max_file_descriptor == 0 ||
			config->max_file_descriptor > 65536) config->max_file_descriptor = 128;
	if(config->prealloc_blks > 64) config->prealloc_blks = 64;

	ffs_root->max_file_descriptor = config->max_file_descriptor;
	ffs_root->prealloc_blks = config->prealloc_blks;
	ffs_root->auto_sync = config->auto_sync;
	//ffs_root->auto_sync = true;

	ffs_root->db_config = fdb_get_default_config();
	ffs_root->db_config.compaction_mode = FDB_COMPACTION_MANUAL;
	ffs_root->db_config.compaction_threshold = 0;
	ffs_root->db_config.block_reusing_threshold = 65;
	ffs_root->db_config.storage_engine = config->storage_engine;
	ffs_root->storage_engine = config->storage_engine;
	if(config->storage_engine == NVMeDirect) {
		ffs_root->db_config.storage_data.nvmedirect.nvmed = nvmed;
	}

	ffs_root->kvs_config = fdb_get_default_kvs_config();

	status = fdb_open(&ffs_root->fhandle, path, &ffs_root->db_config);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = fdb_kvs_open(ffs_root->fhandle, &ffs_root->kvhandle, 
			FFS_META, &ffs_root->kvs_config);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	//read sb
	status = ffs_get_sb(ffs_root->kvhandle, ffs_sb, &ret);
	assert(status == FDB_RESULT_SUCCESS);
	if(status != FDB_RESULT_SUCCESS) {
		free(ffs_root);
		return FFS_RESULT_FAIL;
	}

	ffs_root->ffs_sb = ffs_sb;

	//init ffs_fd_table
	ffs_fd_array = malloc(sizeof(FFS_FD_INFO) * ffs_root->max_file_descriptor);
	if(ffs_fd_array == NULL) {
		free(ffs_root);
		return FFS_RESULT_FAIL;
	}
	for(i=0; i<ffs_root->max_file_descriptor; i++) {
		ffs_fd_array[i].ffs_inode = NULL;
		ffs_fd_array[i].path = NULL;
		ffs_fd_array[i].pos = 0;
		ffs_fd_array[i].flags = 0;
	}

	if(config->storage_engine == LINUX) {
		ffs_root->fd = open(path, O_RDWR);
	}
	else if (config->storage_engine == NVMeDirect || config->storage_engine == NVMeDirect_Self) {
		ffs_root->storage_data.nvmedirect.nvmed = nvmed;
		nvmed_queue = nvmed_queue_create(nvmed, 0);
		nvmed_handle = nvmed_handle_create(nvmed_queue, HANDLE_SYNC_IO);
		ffs_root->storage_data.nvmedirect.queue[NVMeDirect_SYNC] = nvmed_queue;
		ffs_root->storage_data.nvmedirect.handle[NVMeDirect_SYNC] = nvmed_handle;

		nvmed_queue = nvmed_queue_create(nvmed, 0);
		nvmed_handle = nvmed_handle_create(nvmed_queue, HANDLE_SYNC_IO);
		ffs_root->storage_data.nvmedirect.queue[NVMeDirect_ASYNC] = nvmed_queue;
		ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC] = nvmed_handle;
	}

	pthread_spin_init(&ffs_root->meta_lock, 0);
	pthread_spin_init(&ffs_root->blkmap_lock, 0);

	pthread_spin_init(&ffs_root->fd_map, 0);

	ffs_mkdir("/", 0);

	return FFS_RESULT_SUCCESS;
}

static FFS_STATUS ffs_finalize() {
	fdb_status status;
	status = FFS_META_FLUSH_WAL(ffs_root->fhandle);
	assert(status == FDB_RESULT_SUCCESS);

	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = fdb_kvs_close(ffs_root->kvhandle);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	status = fdb_close(ffs_root->fhandle);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	if(ffs_root->storage_engine == LINUX) {
		close(ffs_root->fd);
	}
	else {
		nvmed_handle_destroy(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_SYNC]);
		nvmed_handle_destroy(ffs_root->storage_data.nvmedirect.handle[NVMeDirect_ASYNC]);
		nvmed_queue_destroy(ffs_root->storage_data.nvmedirect.queue[NVMeDirect_SYNC]);
		nvmed_queue_destroy(ffs_root->storage_data.nvmedirect.queue[NVMeDirect_ASYNC]);

		nvmed_close(ffs_root->db_config.storage_data.nvmedirect.nvmed);
	}

	free(ffs_fd_array);
	free(ffs_root);

	return FFS_RESULT_SUCCESS;
}

inline static FFS_STATUS ffs_valid_fd(FFS_FD fd) {
	FFS_FD_INFO* fd_info;

	if(fd >= ffs_root->max_file_descriptor) return FFS_RESULT_FAIL;

	fd_info = ffs_fd_array + fd;
	if(fd_info->path == NULL) return FFS_RESULT_FAIL;

	return FFS_RESULT_SUCCESS;
}

FFS_INODE* ffs_get_inode_from_path(const char* path) {
	FFS_INODE* inode;
	fdb_status status;
	int ret;

	while(true) {
		status = ffs_get_inode(ffs_root->kvhandle, path, inode, &ret);

		if(status != FDB_RESULT_HANDLE_BUSY)
			break;
	}
	if(status != FDB_RESULT_SUCCESS) {
		return NULL;
	}

	return inode;
}

int get_fd(const char *path) {
	int ret;
	int i;
	pthread_spin_lock(&ffs_root->fd_map);
	for(i=3; i<ffs_root->max_file_descriptor; i++) {
		if(ffs_fd_array[i].path == NULL) {
			ret = i;
			break;
		}
	}
	pthread_spin_unlock(&ffs_root->fd_map);

	if(ret > 0) {
		ffs_fd_array[ret].path = malloc(sizeof(char) * strlen(path));
		strcpy(ffs_fd_array[ret].path, path);
	}

	return ret;
}

static int ffs_open(const char* path, int flags) {
	FFS_INODE* inode = NULL;
	time_t now = time(0);
	FFS_FD ret = -1;
	unsigned int i;
	bool create = false;
	fdb_status status;
	//FLAG Check - If no entry & ~O_CREAT? ret Err
	inode = ffs_get_inode_from_path(path);
	if(inode == NULL) {
		if(!(flags & O_CREAT)) return ret;
		inode = malloc(sizeof(FFS_INODE));
		inode->type = FFS_TYPE_REGULAR;
		create = true;
	}
	
	ret = get_fd(path);

	if(ret == -1) {
		if(create == true) free(inode);
		return ret;
	}

	if(create == true) {
		inode->size = 0;
		inode->blocks = 0;
		inode->num_extents = 0;
		inode->ctime = now;
		inode->ref = 0;
		inode->isDelete = false;
	}

	inode->ref++;

	//ctime, mtime, atime update
	inode->atime = now;

	if(create == true) {
		for(i=0; i<NUM_EXTENTS_IN_INODE; i++) {
			inode->extents[i].ext_block = 0;
			inode->extents[i].ext_len = 0;
			inode->extents[i].phys_block = 0;
		}
	}

	//set inode
	status = ffs_set_inode(ffs_root->kvhandle, path, inode);
	assert(status == FDB_RESULT_SUCCESS);

	if(ffs_root->auto_sync) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return FFS_RESULT_FAIL;
	}

	ffs_fd_array[ret].ffs_inode = inode;
	ffs_fd_array[ret].pos = 0;
	ffs_fd_array[ret].flags = flags;

	//return
	return ret;
}

FFS_STATUS ffs_close(FFS_FD fd) {
	FFS_INODE* inode;
	FFS_FD_INFO* fd_info;
	bool need_delete = false;
	fdb_status status;

	if(ffs_valid_fd(fd) == FFS_RESULT_FAIL) return FFS_RESULT_FAIL;
	
	fd_info = ffs_fd_array + fd;

	if(fd_info->is_dirp) ffs_closedir(fd_info->opt);

	inode = ffs_fd_array[fd].ffs_inode;
	inode->ref--;
	status = ffs_set_inode(ffs_root->kvhandle, ffs_fd_array[fd].path, inode);
	assert(status == FDB_RESULT_SUCCESS);
	
	if(inode->ref == 0 && inode->isDelete == true)
		need_delete = true;

	free(inode);

	if(need_delete) ffs_remove_inode(ffs_fd_array[fd].path);

	free(ffs_fd_array[fd].path);
	ffs_fd_array[fd].path = NULL;
	ffs_fd_array[fd].pos = 0;
	ffs_fd_array[fd].flags = 0;

	//return
	return FFS_RESULT_SUCCESS;
}

int ffs_access(const char* path, int mode) {
	FFS_INODE* inode;
	
	inode = ffs_get_inode_from_path(path);
	if(inode == NULL) {
		errno = ENOENT;
		return -1;
	}
	
	return 0;
}

static int ffs_put_blocks(uint64_t phys_blk, uint32_t blk_len) {
	fdb_status status;
	uint32_t remain_blk = blk_len;
	uint8_t* bmap=NULL;
	uint8_t bmap_buf;
	ssize_t ret;
	int pos;
	uint32_t old_bmap_idx = -1, bmap_idx;

	pthread_spin_lock(&ffs_root->blkmap_lock);
	
	phys_blk-= (ffs_root->ffs_sb->num_meta_blocks + 1);
	bmap_idx = (uint32_t)(phys_blk / (FDB_DATA_IN_BLK * 8));

	while(remain_blk) {
		if(old_bmap_idx != bmap_idx) {
			if(bmap!=NULL) {
				ffs_set_bmap(ffs_root->kvhandle, old_bmap_idx, bmap);
			}
			status = ffs_get_bmap(ffs_root->kvhandle, bmap_idx, (void**)&bmap, &ret);
			assert(status == FDB_RESULT_SUCCESS);
			if(status != FDB_RESULT_SUCCESS) break;
			old_bmap_idx = bmap_idx;
		}

		bmap_buf = *(bmap + (phys_blk / 8));
		pos = phys_blk % 8;
		bmap_buf&= ~(1<<pos);
		*(bmap + (phys_blk / 8)) = bmap_buf;

		remain_blk--;

		phys_blk++;
		bmap_idx = (uint32_t)(phys_blk / (FDB_DATA_IN_BLK * 8));
	}
	ffs_set_bmap(ffs_root->kvhandle, bmap_idx, bmap);

	pthread_spin_unlock(&ffs_root->blkmap_lock);

	return blk_len - remain_blk;
}

static int ffs_get_blocks(uint32_t req_blks, uint64_t *phys_blk) {
	fdb_status status;
	uint32_t num_bmap_blocks = ffs_root->ffs_sb->num_bmap_blocks;
	uint8_t* bmap;
	uint8_t bmap_buf;
	uint32_t idx, sub_idx, blk_idx;
	ssize_t ret;
	int pos;
	int numBlks=0;
	uint64_t start_blk;

	if(ffs_root->ffs_sb->num_free_blocks == 0) return 0;

	pthread_spin_lock(&ffs_root->blkmap_lock);

	//Find start empty block
	for(idx=0; idx<num_bmap_blocks; idx++) {
		status = ffs_get_bmap(ffs_root->kvhandle, idx, (void**)&bmap, &ret);
		assert(status == FDB_RESULT_SUCCESS);
		if(status != FDB_RESULT_SUCCESS) {
			continue;
		}
		
		for(sub_idx=0; sub_idx < FDB_DATA_IN_BLK; sub_idx++) {
			bmap_buf = *(bmap+sub_idx);
			pos = __find_first_zero(bmap_buf);
			if(pos == 8) continue;
			break;
		}
		if(pos<8) break;
	}

	bmap_buf |= 1<<pos;
	*(bmap+sub_idx) = bmap_buf;
	
	start_blk = FDB_DATA_IN_BLK*idx + sub_idx*8 + pos;
	start_blk+= ffs_root->ffs_sb->num_meta_blocks+1;

	*phys_blk = start_blk;

	numBlks++;
	pos++;

	//Find contig blocks;
	for(blk_idx=1; blk_idx<req_blks; blk_idx++) {
		if(pos==8) {
			sub_idx++;
			if(sub_idx == FDB_DATA_IN_BLK) {
				ffs_set_bmap(ffs_root->kvhandle, idx, bmap);
				status = ffs_get_bmap(ffs_root->kvhandle, idx++, (void**)&bmap, &ret);
				assert(status == FDB_RESULT_SUCCESS);
				sub_idx=0;
			}
			pos = 0;
		}
	
		bmap_buf = *(bmap+sub_idx);

		if(!(bmap_buf & 1<<pos)) {
			numBlks++;
			bmap_buf |= 1<<pos;
			*(bmap+sub_idx) = bmap_buf;
			pos++;
		}
		else
			break;
	}
	ffs_set_bmap(ffs_root->kvhandle, idx, bmap);

	pthread_spin_lock(&ffs_root->meta_lock);
	ffs_root->ffs_sb->num_free_blocks -= numBlks;
	status = ffs_set_sb(ffs_root->kvhandle, ffs_root->ffs_sb);
	assert(status == FDB_RESULT_SUCCESS);

	pthread_spin_unlock(&ffs_root->meta_lock);
	pthread_spin_unlock(&ffs_root->blkmap_lock);

	return numBlks;
}

FFS_STATUS ffs_add_extents(FFS_FD fd, FFS_INODE *inode, uint32_t ext_block, uint32_t ext_len, uint64_t phys_block) {
	int i;
	uint64_t new_block, curr_block, next_block;
	ssize_t io_completed;
	uint32_t ext_pos;
	uint32_t num_ext_blks;
	void* extent_buf;
	FFS_FD_INFO *fd_info = ffs_fd_array+fd;
	FFS_EXTENTS *new_extent, *extent_blk_ptr;
	FFS_STATUS ret = FFS_RESULT_FAIL;
	fdb_status status;

	// Insert to inode
	if(inode->num_extents < NUM_EXTENTS_IN_INODE) {
		for(i=0; i<NUM_EXTENTS_IN_INODE; i++) {
			if(inode->extents[i].phys_block + inode->extents[i].ext_len == phys_block) {
				inode->extents[i].ext_len+=ext_len;
				ret = FFS_RESULT_SUCCESS;
				break;
			}
			else if(inode->extents[i].ext_len == 0) {
				inode->extents[i].ext_block = ext_block;
				inode->extents[i].ext_len = ext_len;
				inode->extents[i].phys_block = phys_block;

				inode->num_extents++;

				ret = FFS_RESULT_SUCCESS;
				break;
			}
		}
	}
	else if(inode->num_extents == NUM_EXTENTS_IN_INODE) {
		//Check able to merge on last extents?
		if(inode->extents[NUM_EXTENTS_IN_INODE-1].phys_block +
				inode->extents[NUM_EXTENTS_IN_INODE-1].ext_len == phys_block) {
			inode->extents[NUM_EXTENTS_IN_INODE-1].ext_len+=ext_len;

			ret = FFS_RESULT_SUCCESS;
		}
		else {
			//Case No ext blocks and Not in Inode?
			//	Create Extblock
			//	Move last extent to Extblock
			//	Set last ext blocks

			if(ffs_get_blocks(1, &new_block) == 0)
				return ret;
			
			extent_buf = malloc(FFS_BLK_SIZE);
			memset(extent_buf, 0x0, FFS_BLK_SIZE);
			new_extent = extent_buf;

			new_extent[0].ext_block = inode->extents[NUM_EXTENTS_IN_INODE-1].ext_block;
			new_extent[0].ext_len = inode->extents[NUM_EXTENTS_IN_INODE-1].ext_len;
			new_extent[0].phys_block = inode->extents[NUM_EXTENTS_IN_INODE-1].phys_block;
			new_extent[1].ext_block = ext_block;
			new_extent[1].ext_len = ext_len;
			new_extent[1].phys_block = phys_block;

			io_completed = __io_write(fd, extent_buf, FFS_BLK_SIZE, new_block*FFS_BLK_SIZE);
			free(extent_buf);

			if(io_completed != FFS_BLK_SIZE)
				return ret;

			inode->extents[NUM_EXTENTS_IN_INODE-1].ext_block = -1;
			inode->extents[NUM_EXTENTS_IN_INODE-1].ext_len = -1;
			inode->extents[NUM_EXTENTS_IN_INODE-1].phys_block = new_block;

			inode->num_extents++;


			ret = FFS_RESULT_SUCCESS;
		}
	}
	else {
		ext_pos = inode->num_extents - 3; //exts in inode
		next_block = inode->extents[NUM_EXTENTS_IN_INODE-1].phys_block;
		
		// Find the last extents
		num_ext_blks = ext_pos / NUM_EXTENTS_IN_BLKS;
		if(ext_pos % NUM_EXTENTS_IN_BLKS) num_ext_blks++;

		extent_buf = malloc(FFS_BLK_SIZE);
		while(num_ext_blks--) {
			io_completed = __io_read(fd, extent_buf, FFS_BLK_SIZE, next_block*FFS_BLK_SIZE);
			curr_block = next_block;
			if(io_completed != FFS_BLK_SIZE)
				return FFS_RESULT_FAIL;
			extent_blk_ptr = extent_buf;

			next_block = extent_blk_ptr[NUM_EXTENTS_IN_BLKS].phys_block;
			if(num_ext_blks) ext_pos -= NUM_EXTENTS_IN_BLKS;
		}
	
		// Add on last extent?
		if(extent_blk_ptr[ext_pos-1].phys_block + extent_blk_ptr[ext_pos-1].ext_len 
				== phys_block) {
			extent_blk_ptr[ext_pos-1].ext_len += ext_len;
			io_completed = __io_write(fd, extent_buf, FFS_BLK_SIZE, curr_block*FFS_BLK_SIZE);

			if(io_completed == FFS_BLK_SIZE)
				ret = FFS_RESULT_SUCCESS;
		}
		else if(ext_pos == NUM_EXTENTS_IN_BLKS) {

			if(ffs_get_blocks(1, &new_block) == 0)
				return ret;

			extent_blk_ptr[NUM_EXTENTS_IN_BLKS].ext_block = -1;
			extent_blk_ptr[NUM_EXTENTS_IN_BLKS].ext_len= -1;
			extent_blk_ptr[NUM_EXTENTS_IN_BLKS].phys_block = new_block;
			io_completed = __io_write(fd, extent_buf, FFS_BLK_SIZE, curr_block*FFS_BLK_SIZE);

			memset(extent_buf, 0x0, FFS_BLK_SIZE);
			new_extent = extent_buf;

			new_extent[0].ext_block = ext_block;
			new_extent[0].ext_len = ext_len;
			new_extent[0].phys_block = phys_block;
	
			io_completed = __io_write(fd, extent_buf, FFS_BLK_SIZE, new_block*FFS_BLK_SIZE);

			if(io_completed != FFS_BLK_SIZE) {
				free(extent_buf);
				return ret;
			}
			
			inode->num_extents++;
		}
		else {
			extent_blk_ptr[ext_pos].ext_block = ext_block;
			extent_blk_ptr[ext_pos].ext_len = ext_len;
			extent_blk_ptr[ext_pos].phys_block = phys_block;
	
			io_completed = __io_write(fd, extent_buf, FFS_BLK_SIZE, curr_block*FFS_BLK_SIZE);

			if(io_completed != FFS_BLK_SIZE) {
				free(extent_buf);
				return ret;
			}
			
			inode->num_extents++;
		}
		
		free(extent_buf);
		ret = FFS_RESULT_SUCCESS;
	}

	inode->blocks+=ext_len;
	status = ffs_set_inode(ffs_root->kvhandle, fd_info->path, inode);
	assert(status == FDB_RESULT_SUCCESS);
	if(ffs_root->auto_sync) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return FFS_RESULT_FAIL;
	}
	return ret;
}

FFS_STATUS ffs_map_extents(FFS_FD fd, FFS_IOVEC **iovec,
		const void* buf, size_t count, off_t offset) {
	FFS_INODE *inode = FD_TO_INODE(fd);
	FFS_IOVEC *prev_iovec = NULL;
	FFS_IOVEC *new_iovec = NULL;
	uint32_t blk_first, blk_last, blk_offs;
	uint32_t ext_first, ext_last;
	off_t offs_in_blk;
	size_t iov_remain = count;
	ssize_t io_completed;
	FFS_EXTENTS *current_extents;
	uint8_t extents_buf[4096];
	void* buf_offs = (void *)buf;

	blk_first = offset / FFS_BLK_SIZE;
	blk_offs = blk_first;
	blk_last = (offset + count -1) / FFS_BLK_SIZE;
	offs_in_blk = offset % FFS_BLK_SIZE;

	current_extents = &inode->extents[0];

	while(iov_remain) {
		ext_first = current_extents->ext_block;
		ext_last = ext_first + current_extents->ext_len -1;

		if(ext_last >= blk_first) {
			prev_iovec = new_iovec;
			new_iovec = (FFS_IOVEC*)malloc(sizeof(FFS_IOVEC));
			if(prev_iovec!=NULL) prev_iovec->next = new_iovec;
			else *iovec = new_iovec;

			new_iovec->next = NULL;

			if(blk_first >= ext_first && blk_last <= ext_last) {
				new_iovec->start_block = current_extents->phys_block + blk_offs;
				new_iovec->offset = offs_in_blk;
				new_iovec->count = iov_remain;
				new_iovec->buf = buf_offs;

				iov_remain = 0;

				break;
			}
			else if(blk_first >= ext_first && blk_last > ext_last){
				new_iovec->start_block = current_extents->phys_block + blk_offs;
				new_iovec->offset = offs_in_blk;
				new_iovec->count = (ext_last - blk_first + 1) * FFS_BLK_SIZE - offs_in_blk;
				new_iovec->buf = buf_offs;
				
				iov_remain-= new_iovec->count;
			}

			buf_offs += new_iovec->count;
			offs_in_blk = 0;
			blk_first = (offset + new_iovec->count) / FFS_BLK_SIZE;
			blk_offs = 0;
		}
		else {
			blk_offs-=current_extents->ext_len;
		}

		//next extents set
		current_extents++;
		if(current_extents->ext_len == -1) {
			io_completed = __io_read(fd, extents_buf, FFS_BLK_SIZE, 
					current_extents->phys_block * FFS_BLK_SIZE);
			if(io_completed < 0) return FFS_RESULT_FAIL;
			
			current_extents = (FFS_EXTENTS *)extents_buf;
		}
	}
	
	return FFS_RESULT_SUCCESS;
}

ssize_t ffs_io_vecs(FFS_FD fd, FFS_IO io_type, FFS_IOVEC *iovec) {
	FFS_IOVEC *iovec_iter = iovec;
	ssize_t io_completed = 0;

	while(iovec_iter != NULL) {
		if(io_type == FFS_IO_WRITE) {
			io_completed += __io_write(fd, iovec_iter->buf, iovec_iter->count, 
					iovec_iter->start_block * FFS_BLK_SIZE + iovec_iter->offset);
		}
		else if(io_type == FFS_IO_READ) {
			io_completed += __io_read(fd, iovec_iter->buf, iovec_iter->count, 
					iovec_iter->start_block * FFS_BLK_SIZE + iovec_iter->offset);
		}
		else if(io_type == FFS_IO_DISCARD) {
			io_completed += __io_discard(iovec_iter->count, iovec_iter->start_block * FFS_BLK_SIZE);
		}
		iovec_iter = iovec_iter->next;
	}
	
	return io_completed;
}

FFS_STATUS ffs_rename(const char* orig, const char* dest) {
	FFS_INODE new_inode;
	FFS_INODE* old_inode;
	fdb_status status;
	int ret;

	//get old inode
	status = ffs_get_inode(ffs_root->kvhandle, orig, old_inode, &ret);

	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	//copy inode
	memcpy(&new_inode, old_inode, sizeof(FFS_INODE));
	/*
	new_inode.size = old_inode->size;
	new_inode.blocks = old_inode->blocks;
	new_inode.atime = old_inode->atime;
	new_inode.mtime = old_inode->mtime;
	new_inode.ctime = old_inode->ctime;
	new_inode.isDelete = old_inode->isDelete;
	for(i=0; i<NUM_EXTENTS_IN_INODE; i++) {
		new_inode.extents[i].ext_block = old_inode->extents[i].ext_block;
		new_inode.extents[i].ext_len = old_inode->extents[i].ext_len;
		new_inode.extents[i].phys_block = old_inode->extents[i].phys_block;
	}
	*/
	status = ffs_set_inode(ffs_root->kvhandle, dest, &new_inode);
	assert(status == FDB_RESULT_SUCCESS);

	if(ffs_root->auto_sync) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return FFS_RESULT_FAIL;
	}

	//remove old inode
	status = ffs_del_inode(ffs_root->kvhandle, orig);
	assert(status == FDB_RESULT_SUCCESS);

	return FFS_RESULT_SUCCESS;
}


FFS_STATUS ffs_fxstat(int ver, FFS_FD fd, struct stat *buf) {
	FFS_FD_INFO *ffs_fd;
	FFS_INODE *ffs_inode;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	//get_inode
	ffs_fd = ffs_fd_array+fd;
	ffs_inode = ffs_fd->ffs_inode;
	buf->st_size = ffs_inode->size;
	buf->st_blksize = FFS_BLK_SIZE;
	buf->st_blocks = ffs_inode->blocks;
	buf->st_atime = ffs_inode->atime;
	buf->st_mtime = ffs_inode->mtime;
	buf->st_ctime = ffs_inode->ctime;
	if(ffs_inode->type == FFS_TYPE_REGULAR)
		buf->st_mode = S_IFREG;
	else
		buf->st_mode = S_IFDIR;

	return FFS_RESULT_SUCCESS;
}

FFS_STATUS ffs_fxstat64(int ver, FFS_FD fd, struct stat64 *buf) {
	FFS_FD_INFO *ffs_fd;
	FFS_INODE *ffs_inode;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	//get_inode
	ffs_fd = ffs_fd_array+fd;
	ffs_inode = ffs_fd->ffs_inode;
	buf->st_size = ffs_inode->size;
	buf->st_blksize = FFS_BLK_SIZE;
	buf->st_blocks = ffs_inode->blocks;
	buf->st_atime = ffs_inode->atime;
	buf->st_mtime = ffs_inode->mtime;
	buf->st_ctime = ffs_inode->ctime;
	if(ffs_inode->type == FFS_TYPE_REGULAR)
		buf->st_mode = S_IFREG;
	else
		buf->st_mode = S_IFDIR;

	return FFS_RESULT_SUCCESS;
}

extern int errno;
FFS_STATUS ffs_xstat(int ver, const char* path, struct stat *buf) {
	FFS_INODE *ffs_inode = NULL;

	ffs_inode = ffs_get_inode_from_path(path);
	if(ffs_inode == NULL) {
		errno = ENOENT;
		return FFS_RESULT_FAIL;
	}

	//get_inode
	buf->st_size = ffs_inode->size;
	buf->st_blksize = FFS_BLK_SIZE;
	buf->st_blocks = ffs_inode->blocks;
	buf->st_atime = ffs_inode->atime;
	buf->st_mtime = ffs_inode->mtime;
	buf->st_ctime = ffs_inode->ctime;
	if(ffs_inode->type == FFS_TYPE_REGULAR)
		buf->st_mode = S_IFREG;
	else
		buf->st_mode = S_IFDIR;

	return FFS_RESULT_SUCCESS;
}

FFS_STATUS ffs_xstat64(int ver, const char* path, struct stat64 *buf) {
	FFS_INODE *ffs_inode = NULL;

	ffs_inode = ffs_get_inode_from_path(path);
	if(ffs_inode == NULL) {
		errno = ENOENT;
		return FFS_RESULT_FAIL;
	}

	//get_inode
	buf->st_size = ffs_inode->size;
	buf->st_blksize = FFS_BLK_SIZE;
	buf->st_blocks = ffs_inode->blocks;
	buf->st_atime = ffs_inode->atime;
	buf->st_mtime = ffs_inode->mtime;
	buf->st_ctime = ffs_inode->ctime;
	if(ffs_inode->type == FFS_TYPE_REGULAR)
		buf->st_mode = S_IFREG;
	else
		buf->st_mode = S_IFDIR;

	return FFS_RESULT_SUCCESS;
}

FFS_STATUS ffs_lxstat(int ver, const char* path, struct stat *buf) {
	return ffs_xstat(ver, path, buf);
}

FFS_STATUS ffs_lxstat64(int ver, const char* path, struct stat64 *buf) {
	return ffs_xstat64(ver, path, buf);
}

off_t ffs_lseek(FFS_FD fd, off_t offset, int whence) {
	FFS_FD_INFO *ffs_fd;
	FFS_INODE *ffs_inode;
	off_t new_offs;
	fdb_status status;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	ffs_fd = ffs_fd_array+fd;
	new_offs = 0;
	ffs_inode = ffs_fd->ffs_inode;

	switch(whence) {
		case SEEK_SET:
			new_offs = offset;
			break;
		case SEEK_CUR:
			new_offs = ffs_fd->pos + offset;
			break;
		case SEEK_END:
			new_offs = ffs_inode->size + ffs_fd->pos;
			break;
		default:
			return FFS_RESULT_FAIL;
	}
	
	ffs_fd->pos = new_offs;

	if(ffs_inode->size < new_offs) {
		ffs_inode->size = new_offs;
		status = ffs_set_inode(ffs_root->kvhandle, ffs_fd->path, ffs_inode);
		assert(status == FDB_RESULT_SUCCESS);

		if(ffs_root->auto_sync) {
			status = FFS_META_FLUSH(ffs_root->fhandle);
			if(status != FDB_RESULT_SUCCESS)
				return FFS_RESULT_FAIL;
		}
	}

	return new_offs;
}

FFS_STATUS ffs_ftruncate(FFS_FD fd, off_t length) {
	FFS_INODE* ffs_inode;
	FFS_FD_INFO* ffs_fd;
	uint32_t num_blocks;
	uint32_t blk_needs = 0;
	uint32_t alloc_blks = 0;
	uint64_t new_block;
	uint32_t ext_block;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	ffs_fd = ffs_fd_array+fd;
	ffs_inode = ffs_fd->ffs_inode;

	num_blocks = length / FFS_BLK_SIZE;
	if(length % FFS_BLK_SIZE) num_blocks++;

	// shrink?
	if(ffs_inode->size < length && ffs_inode->blocks > num_blocks) {
		//nothing 
		//To-do : remove exists extents?
	}
	// extent?
	else if(ffs_inode->size > length && ffs_inode->blocks < num_blocks) {
		ext_block = ffs_inode->blocks;
		blk_needs = num_blocks - ffs_inode->blocks;
		while(blk_needs) {
			alloc_blks = ffs_get_blocks(blk_needs, &new_block);
			if(alloc_blks == 0)
				return FFS_RESULT_FAIL;

			ffs_add_extents(fd, ffs_inode, ext_block, alloc_blks, new_block);
			blk_needs-=alloc_blks;
			ext_block+=alloc_blks;
		}
	}

	ffs_inode->size = length;

	return FFS_RESULT_SUCCESS;
}

FFS_STATUS ffs_unlink(const char* path) {
	FFS_INODE* inode = NULL;
	FFS_FD_INFO* ffs_fd;
	fdb_status status;
	bool need_delete = false;
	int i;

	for (i=3; i<ffs_root->max_file_descriptor; i++) {
		ffs_fd = ffs_fd_array + i;
		if(ffs_fd->path != NULL && !strcmp(path, ffs_fd->path)) {
			inode = ffs_fd->ffs_inode;
			break;
		}
	}
	
	if(inode == NULL)
		inode = ffs_get_inode_from_path(path);

	if(inode == NULL) return FDB_RESULT_SUCCESS;

	inode->isDelete = true;

	if(inode->ref == 0) need_delete = true;

	status = ffs_set_inode(ffs_root->kvhandle, path, inode);
	assert(status == FDB_RESULT_SUCCESS);
	

	if(need_delete) {
		ffs_remove_inode(path);
		free(inode);
	}

	return FDB_RESULT_SUCCESS;
}

FFS_STATUS ffs_remove_inode(const char* path) {
	FFS_INODE* inode;
	uint32_t num_extents;
	FFS_EXTENTS *current_extents;
	fdb_status status;
	ssize_t io_completed;
	uint8_t extents_buf[4096];

	inode = ffs_get_inode_from_path(path);
	if(inode == NULL) return FDB_RESULT_SUCCESS;

	num_extents = inode->num_extents;
	current_extents = &inode->extents[0];

	while(num_extents) {
		//discard blocks
		__io_discard(current_extents->ext_len * FFS_BLK_SIZE, 
				current_extents->phys_block * FFS_BLK_SIZE);
		//update bmap
		ffs_put_blocks(current_extents->phys_block, current_extents->ext_len);

		num_extents--;
		//next extents set
		current_extents++;
		if(current_extents->ext_len == -1) {
			io_completed = __io_read(0, extents_buf, FFS_BLK_SIZE, 
					current_extents->phys_block * FFS_BLK_SIZE);
			if(io_completed < 0) return FFS_RESULT_FAIL;
			
			current_extents = (FFS_EXTENTS *)extents_buf;
		}
	}

	//free inode
	status = ffs_del_inode(ffs_root->kvhandle, path);
	assert(status == FDB_RESULT_SUCCESS);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;


	return FDB_RESULT_SUCCESS;
}

static ssize_t ffs_pread(FFS_FD fd, void* buf, size_t count, off_t offset) {
	FFS_FD_INFO* fd_info;
	FFS_INODE *inode;
	FFS_IOVEC *iovec;
	ssize_t ret = -1;
	time_t now = time(0);
	fdb_status status;

	//fd valid?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS) return ret;

	//get inode
	fd_info = ffs_fd_array + fd;
	inode = fd_info->ffs_inode;

	if(inode->size == 0)
		return 0;

	if(fd_info->pos >= inode->size) return 0;

	if(inode->size < fd_info->pos + count)
		count = inode->size - fd_info->pos;


	//extent -> iovec Create
	if(ffs_map_extents(fd, &iovec, buf, count, offset) != FFS_RESULT_SUCCESS)
		return 0;

	//IO
	ret = ffs_io_vecs(fd, FFS_IO_READ, iovec);

	//Modify atime
	if(ret != -1) {
		inode->atime = now;
		status = ffs_set_inode(ffs_root->kvhandle, fd_info->path, inode);
		assert(status == FDB_RESULT_SUCCESS);
		if(ffs_root->auto_sync) {
			status = FFS_META_FLUSH(ffs_root->fhandle);
			if(status != FDB_RESULT_SUCCESS)
				return 0;
		}
	}
	//return copies
	return ret;
}

static ssize_t ffs_read(FFS_FD fd, void* buf, size_t count) {
	ssize_t io_completed;
	FFS_FD_INFO *ffs_fd;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	ffs_fd = ffs_fd_array+fd;
	//FLAG CHECK
	if(ffs_fd->flags & O_WRONLY )
		return FFS_RESULT_NOPERM;

	io_completed = ffs_pread(fd, buf, count, ffs_fd->pos);
	if(io_completed > 0)
		ffs_lseek(fd, io_completed, SEEK_CUR);

	return io_completed;
}

static ssize_t ffs_pwrite(FFS_FD fd, const void* buf, size_t count, off_t offset) {
	FFS_FD_INFO* fd_info;
	FFS_INODE *inode;
	FFS_IOVEC *iovec;
	ssize_t ret = -1;
	//uint32_t blk_first, blk_last;
	uint32_t blk_last;
	uint32_t blk_needs = 0;
	uint32_t ext_block;
	uint64_t new_block;
	int alloc_blks;
	time_t now = time(0);
	fdb_status status;
	//fd valid?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS) return ret;

	//get inode
	fd_info = ffs_fd_array + fd;
	inode = fd_info->ffs_inode;

	//blk_first = offset / FFS_BLK_SIZE;
	blk_last = (offset + count -1) / FFS_BLK_SIZE;

	//count + offset > filesize ? get_blocks
	if(blk_last >= inode->blocks) blk_needs = blk_last - inode->blocks + 1;
	if(blk_needs > 0 && blk_needs < ffs_root->prealloc_blks) blk_needs=ffs_root->prealloc_blks;
	//make extents
	ext_block = inode->blocks;
	while(blk_needs) {
		alloc_blks = ffs_get_blocks(blk_needs, &new_block);
		if(alloc_blks == 0)
			return ret;

		ffs_add_extents(fd, inode, ext_block, alloc_blks, new_block);
		blk_needs-=alloc_blks;
		ext_block+=alloc_blks;
	}

	//extent -> iovec Create
	if(ffs_map_extents(fd, &iovec, buf, count, offset) != FFS_RESULT_SUCCESS)
		return ret;

	//IO
	ret = ffs_io_vecs(fd, FFS_IO_WRITE, iovec);
	//Modify mtime
	if(ret != -1) {
		inode->mtime = now;
		if(inode->size < offset+ret)
			inode->size = offset + ret;
		status = ffs_set_inode(ffs_root->kvhandle, fd_info->path, inode);
		assert(status == FDB_RESULT_SUCCESS);
		if(ffs_root->auto_sync) {
			status = FFS_META_FLUSH(ffs_root->fhandle);
			if(status != FDB_RESULT_SUCCESS) {
				return ret = 0;
			}
		}
	}

	//return copies
	return ret;
}

static ssize_t ffs_write(FFS_FD fd, const void* buf, size_t count) {
	ssize_t io_completed;
	FFS_FD_INFO *ffs_fd;

	//FD is exists?
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;
	
	if(count == 0) return 0;

	ffs_fd = ffs_fd_array+fd;
	//FLAG CHECK
	if(ffs_fd->flags && O_RDONLY)
		return FFS_RESULT_NOPERM;

	io_completed = ffs_pwrite(fd, buf, count, ffs_fd->pos);
	if(io_completed > 0)
		ffs_lseek(fd, io_completed, SEEK_CUR);

	return io_completed;
}

int ffs_sync() {
	return __io_sync();
}

int ffs_syncfs(FFS_FD fd) {
	return ffs_sync();
}

int ffs_fsync(FFS_FD fd) {
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS) return -EBADF;
	return __io_fsync(fd, false);
}

int ffs_fdatasync(FFS_FD fd) {
	if(ffs_valid_fd(fd) != FFS_RESULT_SUCCESS) {
		return -EBADF;
	}
	return 0;

	//return __io_fsync(fd, true);
}

DIR* ffs_opendir(const char* path) {
	char* startDir, *endDir;
	int path_len, new_len;
	FFS_DIR *new_dir;
	fdb_status status;

	new_dir = (FFS_DIR*)malloc(sizeof(FFS_DIR));

	path_len = strlen(path);
	
	if(path[path_len-1] == '/') {
		startDir = (char *)path;
		endDir = (char *)malloc(path_len);
		strcpy(endDir, path);
		endDir[path_len-1] = '0';
		new_len = path_len;
	}
	else {
		startDir = (char *)malloc(path_len + 1);
		strcpy(startDir, path);
		startDir[path_len] = '/';
		startDir[path_len+1] = '\0';
		endDir = (char *)malloc(path_len + 1);
		strcpy(endDir, path);
		endDir[path_len] = '0';
		endDir[path_len+1] = '\0';
		new_len = path_len+1;
	}

	status = fdb_iterator_init(ffs_root->kvhandle, 
			&new_dir->iterator, startDir, new_len, endDir, new_len, FDB_ITR_SKIP_MAX_KEY);

	if(status != FDB_RESULT_SUCCESS) {
		return NULL;
	}
	
	new_dir->fd = 8192;
	new_dir->curPos = 0;
	return (DIR*)new_dir;
}

FFS_STATUS ffs_closedir(DIR* _dirp) {
	FFS_DIR *dirp = (FFS_DIR*)_dirp;
	fdb_iterator_close(dirp->iterator);
	
	free(dirp);

	return FFS_RESULT_SUCCESS;
}

struct dirent* ffs_readdir(DIR* _dirp) {
	FFS_DIR *dirp = (FFS_DIR*)_dirp;
	fdb_doc *doc = NULL;
	fdb_status status;

	if(dirp->curPos == 0) {
		dirp->dir.d_ino = 0;
		dirp->dir.d_off = 0;
		dirp->dir.d_reclen = 1;
		dirp->dir.d_type = DT_DIR;
		memset(dirp->dir.d_name, 0x0, 255);
		strncpy(dirp->dir.d_name, ".", 1);
	}
	else if(dirp->curPos == 1) {
		dirp->dir.d_ino = 0;
		dirp->dir.d_off = 0;
		dirp->dir.d_reclen = 2;
		dirp->dir.d_type = DT_DIR;
		memset(dirp->dir.d_name, 0x0, 255);
		strncpy(dirp->dir.d_name, "..", 2);
	}
	else {
		status = fdb_iterator_get(dirp->iterator, &doc);
		if(status != FDB_RESULT_SUCCESS) {
			return NULL;
		}

		dirp->dir.d_ino = 0;
		dirp->dir.d_off = 0;
		dirp->dir.d_reclen = doc->keylen;
		dirp->dir.d_type = DT_REG;
		memset(dirp->dir.d_name, 0x0, 255);
		strncpy(dirp->dir.d_name, doc->key, doc->keylen);
		fdb_iterator_next(dirp->iterator);
	}
	dirp->curPos++;

	return &dirp->dir;
}

int ffs_readdir64_r(DIR *__restrict __dirp, 
		struct dirent64 *__restrict __entry, struct dirent64 **__restrict __result) {
	FFS_DIR *dirp = (FFS_DIR*)__dirp;
	fdb_doc *doc = NULL;
	fdb_status status;

	if(dirp->curPos == 0) {
		__entry->d_ino = 0;
		__entry->d_off = 0;
		__entry->d_reclen = 1;
		__entry->d_type = DT_DIR;
		memset(__entry->d_name, 0x0, 255);
		strncpy(__entry->d_name, ".", 1);
	}
	else if(dirp->curPos == 1) {
		__entry->d_ino = 0;
		__entry->d_off = 0;
		__entry->d_reclen = 2;
		__entry->d_type = DT_DIR;
		memset(__entry->d_name, 0x0, 255);
		strncpy(__entry->d_name, "..", 2);
		status = fdb_iterator_get(dirp->iterator, &doc);
	}
	else {
		status = fdb_iterator_get(dirp->iterator, &doc);
		if(status != FDB_RESULT_SUCCESS) {
			*__result = NULL;
			return 0;
		}
		__entry->d_ino = 0;
		__entry->d_off = 0;
		__entry->d_reclen = doc->keylen;
		__entry->d_type = DT_REG;
		memset(__entry->d_name, 0x0, 255);
		strncpy(__entry->d_name, doc->key, doc->keylen);

		status = fdb_iterator_next(dirp->iterator);

	/*	if(status != FDB_RESULT_ITERATOR_FAIL)
			__result = &__entry;
		else
			*__result = NULL;
	*/
	}
	*__result = __entry;
	dirp->curPos++;

	return 0;
}

/*
int	ffs_openat(int dirfd, const char *pathname, int flags) {
	FFS_DIR *dirp;
	FFS_FD_INFO* fd_info;
	int fd;

	fd = ffs_open(pathname, 0);
	if(fd < 0) return -1;

	dirp = ffs_opendir(pathname);

	fd_info = ffs_fd_array + fd;
	fd_info->is_dirp = 1;
	fd_info->opt = dirp;

	return fd;
}

int ffs_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
	FFS_DIR *ffs_dirp;
	FFS_FD_INFO* fd_info;

	if(ffs_valid_fd(fd) == FFS_RESULT_FAIL) return FFS_RESULT_FAIL;

	fd_info = ffs_fd_array + fd;

	if(!fd_info->is_dirp) return -1;

	return 0;
}
*/
int ffs_mkdir(const char* pathname, mode_t mode) {
	FFS_INODE *ffs_inode;
	time_t now = time(0);
	fdb_status status;
	ffs_inode = ffs_get_inode_from_path(pathname);
	//EEXIST
	if(ffs_inode != NULL)
		return FFS_RESULT_FAIL;
	
	// Create inode, inode type = directory
	ffs_inode = malloc(sizeof(FFS_INODE));
	ffs_inode->size = 0;
	ffs_inode->blocks = 0;
	ffs_inode->num_extents = 0;
	ffs_inode->type = FFS_TYPE_DIRECTORY;
	ffs_inode->ctime = now;

	status = ffs_set_inode(ffs_root->kvhandle, pathname, ffs_inode);
	assert(status == FDB_RESULT_SUCCESS);
	if(ffs_root->auto_sync) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return FFS_RESULT_FAIL;
	}

	return FFS_RESULT_SUCCESS;
}

int ffs_rmdir(const char* pathname) {
	bool isEmpty = false;
	FFS_INODE *ffs_inode;
	DIR* dirp;
	fdb_status status;

	ffs_inode = ffs_get_inode_from_path(pathname);
	//ENOENT
	if(ffs_inode != NULL)
		return FFS_RESULT_FAIL;

	//ENOTDIR
	if(ffs_inode->type != FFS_TYPE_DIRECTORY)
		return FFS_RESULT_FAIL;

	dirp = ffs_opendir(pathname);
	if(ffs_readdir(dirp) == NULL)
		isEmpty = true;
	ffs_closedir(dirp);
	
	//ENOTEMPTY
	if(!isEmpty)
		return FFS_RESULT_FAIL;

	free(ffs_inode);

	status = ffs_del_inode(ffs_root->kvhandle, pathname);
	assert(status == FDB_RESULT_SUCCESS);
	if(status != FDB_RESULT_SUCCESS)
		return FFS_RESULT_FAIL;

	return FFS_RESULT_SUCCESS;
}

int ffs_fallocate(int fd, int mode, off_t offset, off_t len) {
	FFS_FD_INFO* fd_info;
	FFS_INODE* inode;
	uint32_t blk_last;
	uint32_t blk_needs = 0;
	uint32_t ext_block;
	uint64_t new_block;
	int alloc_blks;
	fdb_status status;
	time_t now = time(0);

	//get inode
	fd_info = ffs_fd_array + fd;
	inode = fd_info->ffs_inode;

	//blk_first = offset / FFS_BLK_SIZE;
	blk_last = (offset + len -1) / FFS_BLK_SIZE;

	//len + offset > filesize ? get_blocks
	if(blk_last >= inode->blocks) blk_needs = blk_last - inode->blocks + 1;
	if(blk_needs > 0 && blk_needs < ffs_root->prealloc_blks) blk_needs=ffs_root->prealloc_blks;
	//make extents
	ext_block = inode->blocks;
	while(blk_needs) {
		alloc_blks = ffs_get_blocks(blk_needs, &new_block);
		if(alloc_blks == 0)
			return -1;

		ffs_add_extents(fd, inode, ext_block, alloc_blks, new_block);
		blk_needs-=alloc_blks;
		ext_block+=alloc_blks;
	}

	//Modify mtime
	inode->mtime = now;
	if(inode->size < offset+len)
		inode->size = offset + len;
	status = ffs_set_inode(ffs_root->kvhandle, fd_info->path, inode);
	assert(status == FDB_RESULT_SUCCESS);
	if(ffs_root->auto_sync) {
		status = FFS_META_FLUSH(ffs_root->fhandle);
		if(status != FDB_RESULT_SUCCESS)
			return -1;
	}

	return FFS_RESULT_SUCCESS;
};

FFS_STATUS ffs_truncate(const char *path, off_t length) {

	return FFS_RESULT_SUCCESS;
}

int ffs_fcntl(int fd, int cmd, ...) {
	return FFS_RESULT_SUCCESS;
}

int ffs_flock(int fd, int operation) {
	return FFS_RESULT_SUCCESS;
}

// dlsyms
struct fs_ops fsops = {
	.fs_name = "ForestFS",
	.open = ffs_open,
	.read = ffs_read,
	.write = ffs_write,
	.close = ffs_close,
	.__xstat = ffs_xstat,
	.__lxstat = ffs_lxstat,
	.__fxstat = ffs_fxstat,
	.__xstat64 = ffs_xstat64,
	.__lxstat64 = ffs_lxstat64,
	.__fxstat64 = ffs_fxstat64,
	.lseek = ffs_lseek,
	.pread = ffs_pread,
	.pwrite = ffs_pwrite,
	.fallocate = ffs_fallocate,
	.access = ffs_access,
	.fcntl = ffs_fcntl,
	.flock = ffs_flock,
	.fsync = ffs_fsync,
	.fdatasync = ffs_fdatasync,
	.truncate = ffs_truncate,
	.ftruncate = ffs_ftruncate,
	.rename = ffs_rename,
	.mkdir = ffs_mkdir,
	.rmdir = ffs_rmdir,
	.sync = ffs_sync,
	.syncfs = ffs_syncfs,

	.opendir = ffs_opendir,
	.readdir = ffs_readdir,
	.readdir64_r = ffs_readdir64_r,
	.closedir = ffs_closedir,

	//.openat = ffs_openat,
	//.getdents = ffs_getdents,

	.init = ffs_init,
	.finalize = ffs_finalize,
	.format = ffs_format,
};
