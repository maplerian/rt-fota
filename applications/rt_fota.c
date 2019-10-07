/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2019-09-22     Warfalcon    first version
 */

#include <rt_fota.h>

#ifndef RT_FOTA_ALGO_BUFF_SIZE
#define RT_FOTA_ALGO_BUFF_SIZE				4096
#endif

#ifndef RT_FOTA_ALGO_AES_IV
#define RT_FOTA_ALGO_AES_IV  				"0123456789ABCDEF"
#endif

#ifndef RT_FOTA_ALGO_AES_KEY
#define RT_FOTA_ALGO_AES_KEY 				"0123456789ABCDEF0123456789ABCDEF"
#endif

#ifndef RT_FOTA_BLOCK_HEADER_SIZE
#define RT_FOTA_BLOCK_HEADER_SIZE			4
#endif

#ifndef RT_FOTA_FASTLZ_BUFFER_SIZE			
#define RT_FOTA_FASTLZ_BUFFER_SIZE			4096
#endif

#ifndef RT_FOTA_FASTLZ_BUFFER_PADDING
#define RT_FOTA_FASTLZ_BUFFER_PADDING 		FASTLZ_BUFFER_PADDING(RT_FOTA_FASTLZ_BUFFER_SIZE)
#endif

const char boot_log_buf[] = 
" ____ _____	 _____ ___ _____  _ 	   \r\n\
|  _ \\_   _|	|  ___/ _ \\_	_|/ \\	   \r\n\
| |_) || |_____| |_ | | | || | / _ \\      \r\n\
|  _ < | |_____|  _|| |_| || |/ ___ \\     \r\n\
|_| \\_\\|_|	 |_|   \\___/ |_/_/   \\_\\\r\n";
									  
typedef struct {
	char type[4];
	rt_uint16_t fota_algo;
	rt_uint8_t fm_time;
	char app_part_name[16];
	char download_version[24];
	char current_version[24];
	rt_uint32_t code_crc;
	rt_uint32_t hash_val;
	rt_uint32_t raw_size;
	rt_uint32_t com_size;
	rt_uint32_t head_crc;
} rt_fota_part_head, *rt_fota_part_head_t;

typedef void (*rt_fota_app_func)(void);	
static rt_fota_app_func app_func;

static rt_fota_part_head fota_part_head;

static void rt_fota_print_log(void)
{
	rt_kprintf("%s\r\n", boot_log_buf);
	rt_kprintf("2016 - 2019 Copyright by radiation \r\n");
	rt_kprintf("Version: %s build %s\r\n", RT_FOTA_SW_VERSION, __DATE__);
}

static int rt_fota_boot_verify(void)
{
	int fota_res = RT_FOTA_NO_ERR;

	rt_memset(&fota_part_head, 0x0, sizeof(rt_fota_part_head));
	
	/* partition initial */
	fal_init(); 

	extern int fal_init_check(void);
	/* verify partition */
	if (fal_init_check() != 1)
    {
    	log_d("Partition initialized failed!");
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_boot_verify;
    }

__exit_boot_verify:
	return fota_res;
}

int rt_fota_part_fw_verify(const char *part_name)
{
#define RT_FOTA_CRC_BUFF_SIZE		4096
#define RT_FOTA_CRC_INIT_VAL		0xffffffff

	int fota_res = RT_FOTA_NO_ERR;
	const struct fal_partition *part;
	rt_fota_part_head part_head;
	rt_uint8_t *body_buf = RT_NULL;
	rt_uint32_t body_crc = RT_FOTA_CRC_INIT_VAL;
	rt_uint32_t hdr_crc;

	if (part_name == RT_NULL)
	{
		log_d("Invaild paramenter input!");
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_partition_verify;
	}

	part = fal_partition_find(part_name);
	if (part == RT_NULL)
	{		
		log_d("Partition[%s] not found.", part_name);
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_partition_verify;
	}

	/* read the head of RBL files */
	if (fal_partition_read(part, 0, (rt_uint8_t *)&part_head, sizeof(rt_fota_part_head)) < 0)
	{
		log_d("Partition[%s] read error!", part->name);
		fota_res = RT_FOTA_PART_READ_ERR;
		goto __exit_partition_verify;
	}

	extern rt_uint32_t rt_fota_crc(rt_uint8_t *buf, rt_uint32_t len);
	hdr_crc = rt_fota_crc((rt_uint8_t *)&part_head, sizeof(rt_fota_part_head));
	if (hdr_crc != 0x0)
	{
		log_d("Partition[%s] head CRC32 error!", part->name);
		fota_res = RT_FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}
	
	if (rt_strcmp(part_head.type, "RBL") != 0)
	{
		log_d("Partition[%s] type[%s] not surport.", part->name, part_head.type);
		fota_res = RT_FOTA_CHECK_FAILED;
		goto __exit_partition_verify;
	}

	if (fal_partition_find(part_head.app_part_name) == RT_NULL)
	{
		log_d("Partition[%s] not found.", part_head.app_part_name);
		fota_res = RT_FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}

	body_buf = rt_malloc(RT_FOTA_CRC_BUFF_SIZE);
	if (body_buf)
	{
		log_d("Not enough memory for body CRC32 verify.");	
		fota_res = RT_FOTA_NO_MEM_ERR;
		goto __exit_partition_verify;
	}

	for (int body_pos = 0; body_pos < part_head.com_size;)
	{	
		int body_read_len = fal_partition_read(part, sizeof(rt_fota_part_head) + body_pos, body_buf, RT_FOTA_CRC_BUFF_SIZE);
		if (body_read_len > 0) 
		{
			extern rt_uint32_t rt_fota_step_crc(rt_uint32_t crc, rt_uint8_t *buf, rt_uint32_t len);
			body_crc = rt_fota_step_crc(body_crc, body_buf, body_read_len);	
			body_pos = body_pos + body_read_len;
		}
		else
		{
			log_d("Partition[%s] read error!", part->name);		
			fota_res = RT_FOTA_PART_READ_ERR;
			goto __exit_partition_verify;
		}
	}
	body_crc = body_crc ^ RT_FOTA_CRC_INIT_VAL;
	
	if (body_crc != part_head.code_crc)
	{
		log_d("Partition[%s] firmware integrity verify failed.", part->name);		
		fota_res = RT_FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}

__exit_partition_verify:
	if (fota_res == RT_FOTA_NO_ERR)
	{
		rt_enter_critical();
		rt_memcpy(&fota_part_head, &part_head, sizeof(rt_fota_part_head));
		rt_exit_critical();

		log_i("partition[%s] verify success!", part->name);
	}
	else
	{
		rt_enter_critical();
		rt_memset(&fota_part_head, 0x0, sizeof(rt_fota_part_head));
		rt_exit_critical();
		
		log_i("Partition[%s] verify failed!", part->name);
	}

	if (body_buf)
		rt_free(body_buf);
	
	return fota_res;
}

int rt_fota_check_upgrade(void)
{
	int is_upgrade = 0;

	if (rt_strcmp(fota_part_head.download_version, fota_part_head.current_version) == 0)
	{
		is_upgrade = 1;
		log_d("Application need upgrade.");
		goto __exit_check_upgrade;
	}

__exit_check_upgrade:
	return is_upgrade;
}

int rt_fota_erase_app_part(void)
{
	int fota_res = RT_FOTA_NO_ERR;
	const struct fal_partition *part;

	part = fal_partition_find(fota_part_head.app_part_name);
	if (part == RT_NULL)
	{
		log_d("Erase partition[%s] not found.", fota_part_head.app_part_name);
		fota_res = RT_FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_erase;
	}

	if (fal_partition_erase(part, 0, fota_part_head.raw_size) < 0)
	{
		log_d("Partition[%s] erase failed!", part->name);
		fota_res = RT_FOTA_PART_ERASE_ERR;
		goto __exit_partition_erase;
	}

__exit_partition_erase:
	if (fota_res == RT_FOTA_NO_ERR)
	{
		log_i("Partition[%s] erase %d bytes success!", part->name, fota_part_head.raw_size);
	}
	return fota_res;
}

int rt_fota_write_app_part(int fw_pos, rt_uint8_t *fw_buf, int fw_len)
{
	int rt_fota_res = RT_FOTA_NO_ERR;
	const struct fal_partition *part;

	part = fal_partition_find(fota_part_head.app_part_name);
	if (part == RT_NULL)
	{
		log_d("Erase partition[%s] not found.", fota_part_head.app_part_name);
		rt_fota_res = RT_FOTA_FW_VERIFY_FAILED;
		goto __partition_write_exit;
	}

	if (fal_partition_write(part, fw_pos, fw_buf, fw_len) < 0)
	{
		log_d("Partition[%s] write failed!", part->name);
		rt_fota_res = RT_FOTA_PART_WRITE_ERR;
		goto __partition_write_exit;
	}
__partition_write_exit:
	if (rt_fota_res == RT_FOTA_NO_ERR)
	{
		log_i("Partition[%s] write %d bytes success!", part->name, fw_len);
	}
	return rt_fota_res;
}

static int rt_fota_read_part(const struct fal_partition *part, int read_pos, tiny_aes_context *aes_ctx, rt_uint8_t *aes_iv, rt_uint8_t *decrypt_buf, rt_uint32_t decrypt_len)
{
	int fota_err = RT_FOTA_NO_ERR;
	rt_uint8_t *encrypt_buf = RT_NULL;

	if ((part == RT_NULL) || (decrypt_buf == RT_NULL) 
		|| (decrypt_len % 16 != 0) || (decrypt_len > RT_FOTA_ALGO_BUFF_SIZE))
	{
		fota_err = RT_FOTA_GENERAL_ERR;
		goto __exit_read_decrypt;
	}

	/* Not use AES256 algorithm */
	if (aes_ctx == RT_NULL || aes_iv == RT_NULL)
	{
		fota_err = fal_partition_read(part, sizeof(rt_fota_part_head) + read_pos, decrypt_buf, decrypt_len);
		if (fota_err <= 0)
		{
			fota_err = RT_FOTA_PART_READ_ERR;
		}
		goto __exit_read_decrypt;
	}

	encrypt_buf = rt_malloc(RT_FOTA_ALGO_BUFF_SIZE);
	if (encrypt_buf == RT_NULL)
	{
		fota_err = RT_FOTA_GENERAL_ERR;
		goto __exit_read_decrypt;
	}
	rt_memset(encrypt_buf, 0x0, RT_FOTA_ALGO_BUFF_SIZE);

	fota_err = fal_partition_read(part, sizeof(rt_fota_part_head) + read_pos, encrypt_buf, RT_FOTA_ALGO_BUFF_SIZE);
	if (fota_err <= 0 || fota_err % 16 != 0)
	{
		fota_err = RT_FOTA_PART_READ_ERR;
		goto __exit_read_decrypt;
	}

	tiny_aes_crypt_cbc(aes_ctx, AES_DECRYPT, decrypt_len, aes_iv, encrypt_buf, decrypt_buf);
__exit_read_decrypt:
	if (encrypt_buf)
		rt_free(encrypt_buf);
	
	return fota_err;
}

int rt_fota_upgrade(const char *part_name)
{
	int fota_err = RT_FOTA_NO_ERR;
	
	const struct fal_partition *part;
	rt_fota_part_head_t part_head = RT_NULL;
	
	tiny_aes_context *aes_ctx = RT_NULL;
	rt_uint8_t *aes_iv = RT_NULL;
	rt_uint8_t *crypt_buf = RT_NULL;
	
	int fw_raw_pos = 0;
	rt_uint32_t total_copy_size = 0;

	rt_uint8_t block_hdr_buf[RT_FOTA_BLOCK_HEADER_SIZE];	
	rt_uint32_t block_hdr_pos = RT_FOTA_ALGO_BUFF_SIZE;
	rt_uint32_t block_size = 0;
	rt_uint32_t dcprs_size = 0;
	rt_uint8_t *cmprs_buff = RT_NULL;
	rt_uint8_t *dcprs_buff = RT_NULL;

	if (part_name == RT_NULL)
	{
		log_d("Invaild paramenter input!");
		fota_err = RT_FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}

	part = fal_partition_find(part_name);
	if (part == RT_NULL)
	{		
		log_d("Upgrade partition[%s] not found.", part_name);
		fota_err = RT_FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}
	
	/* Application partition erase */
	fota_err = rt_fota_erase_app_part();
	if (fota_err != RT_FOTA_NO_ERR)
	{
		goto __exit_upgrade;
	}

	/* rt_fota_erase_app_part() has check fota_part_head vaild already */
	part_head = &fota_part_head;

	/* AES256 algorithm enable */
	if ((part_head->fota_algo & RT_FOTA_CRYPT_STAT_MASK) == RT_FOTA_CRYPT_ALGO_AES256)
	{
		aes_ctx = rt_malloc(sizeof(tiny_aes_context));	
		aes_iv = rt_malloc(rt_strlen(RT_FOTA_ALGO_AES_IV) + 1);
		crypt_buf = rt_malloc(RT_FOTA_ALGO_BUFF_SIZE);
		if (aes_ctx == RT_NULL || aes_iv == RT_NULL || crypt_buf == RT_NULL)
		{
			log_d("Not enough memory for firmware hash verify.");
			fota_err = RT_FOTA_NO_MEM_ERR;
			goto __exit_upgrade;
		}

		rt_memset(aes_iv, 0x0, rt_strlen(RT_FOTA_ALGO_AES_IV) + 1);
		rt_memcpy(aes_iv, RT_FOTA_ALGO_AES_IV, rt_strlen(RT_FOTA_ALGO_AES_IV));
		tiny_aes_setkey_dec(aes_ctx, (rt_uint8_t *)RT_FOTA_ALGO_AES_KEY, 256);
	}
	
	/* If enable compress function */	
	if ((part_head->fota_algo & RT_FOTA_CMPRS_STAT_MASK) != RT_FOTA_CMPRS_ALGO_FASTLZ) 
	{
		cmprs_buff = rt_malloc(RT_FOTA_FASTLZ_BUFFER_SIZE + RT_FOTA_FASTLZ_BUFFER_PADDING);
		dcprs_buff = rt_malloc(RT_FOTA_FASTLZ_BUFFER_SIZE);	
		if (cmprs_buff == RT_NULL || dcprs_buff == RT_NULL)
		{
			log_d("Not enough memory for firmware hash verify.");
			fota_err = RT_FOTA_NO_MEM_ERR;
			goto __exit_upgrade;
		}
	}

	log_i("Start to copy firmware from %s to %s partition:", part->name, part_head->app_part_name);
	while (fw_raw_pos < part_head->com_size)
	{
		if ((part_head->fota_algo & RT_FOTA_CMPRS_STAT_MASK) != RT_FOTA_CMPRS_ALGO_FASTLZ) 
		{		
			if (block_hdr_pos >= RT_FOTA_ALGO_BUFF_SIZE)
			{
				fota_err = rt_fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, RT_FOTA_ALGO_BUFF_SIZE);
				if (fota_err < 0)
				{
					log_d("AES256 algorithm failed.");
					fota_err = RT_FOTA_PART_READ_ERR;
					goto __exit_upgrade;
				}
				fw_raw_pos += fota_err;

				rt_memcpy(block_hdr_buf, crypt_buf, RT_FOTA_BLOCK_HEADER_SIZE);
				block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];
				rt_memset(cmprs_buff, 0x0, RT_FOTA_FASTLZ_BUFFER_SIZE + RT_FOTA_FASTLZ_BUFFER_PADDING);
				rt_memcpy(cmprs_buff, &crypt_buf[RT_FOTA_BLOCK_HEADER_SIZE], block_size);

				block_hdr_pos = RT_FOTA_BLOCK_HEADER_SIZE + block_size;
			}
			else
			{
				rt_uint8_t hdr_tmp_pos = 0;
				while (block_hdr_pos < RT_FOTA_ALGO_BUFF_SIZE)
				{
					if (hdr_tmp_pos < RT_FOTA_BLOCK_HEADER_SIZE)
					{
						block_hdr_buf[hdr_tmp_pos++] = crypt_buf[block_hdr_pos++];
					}
					else
					{
						block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];
						
						rt_memset(cmprs_buff, 0x0, RT_FOTA_FASTLZ_BUFFER_SIZE + RT_FOTA_FASTLZ_BUFFER_PADDING);
						if (block_size > (RT_FOTA_ALGO_BUFF_SIZE - block_hdr_pos))
						{								
							rt_memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], (RT_FOTA_ALGO_BUFF_SIZE - block_hdr_pos));
							fota_err = rt_fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, RT_FOTA_ALGO_BUFF_SIZE);
							if (fota_err < 0)
							{
								log_d("AES256 algorithm failed.");
								fota_err = RT_FOTA_PART_READ_ERR;
								goto __exit_upgrade;
							}
							fw_raw_pos += fota_err;

							rt_memcpy(&cmprs_buff[RT_FOTA_ALGO_BUFF_SIZE - block_hdr_pos], &crypt_buf[0], (block_size +  block_hdr_pos) - RT_FOTA_ALGO_BUFF_SIZE);
							block_hdr_pos = (block_size +  block_hdr_pos) - RT_FOTA_ALGO_BUFF_SIZE;
						}
						else
						{
							rt_memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], block_size);
							block_hdr_pos = block_hdr_pos + block_size;
						}						
						break;
					}
				}
				
				if (hdr_tmp_pos < RT_FOTA_BLOCK_HEADER_SIZE)
				{				
					fota_err = rt_fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, RT_FOTA_ALGO_BUFF_SIZE);
					if (fota_err < 0)
					{
						log_d("AES256 algorithm failed.");
						fota_err = RT_FOTA_PART_READ_ERR;
						goto __exit_upgrade;
					}
					fw_raw_pos += fota_err;

					block_hdr_pos = 0;
					while (hdr_tmp_pos < RT_FOTA_BLOCK_HEADER_SIZE)
					{
						block_hdr_buf[hdr_tmp_pos++] = crypt_buf[block_hdr_pos++];
					}
					block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];

					rt_memset(cmprs_buff, 0x0, RT_FOTA_FASTLZ_BUFFER_SIZE + RT_FOTA_FASTLZ_BUFFER_PADDING);
					rt_memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], block_size);

					block_hdr_pos = (block_hdr_pos + block_size) % RT_FOTA_ALGO_BUFF_SIZE;
				}
			}

			rt_memset(dcprs_buff, 0x0, RT_FOTA_FASTLZ_BUFFER_SIZE);			
			dcprs_size = fastlz_decompress((const void *)&cmprs_buff[0], block_size, &dcprs_buff[0], RT_FOTA_FASTLZ_BUFFER_SIZE);
			if (dcprs_size <= 0)
			{
				log_d("Fastlz decompress failed.");
				fota_err = RT_FOTA_GENERAL_ERR;
				goto __exit_upgrade;
			}
			
			if (rt_fota_write_app_part(total_copy_size, dcprs_buff, dcprs_size) < 0)
			{
				fota_err = RT_FOTA_COPY_FAILED;
				goto __exit_upgrade;
			}

			total_copy_size += dcprs_size;
			rt_kprintf(">");
		}
		else if ((part_head->fota_algo & RT_FOTA_CMPRS_STAT_MASK) != RT_FOTA_CMPRS_ALGO_QUICKLZ) 
		{
			log_d("Quicklz not supported.");
			fota_err = RT_FOTA_ALGO_NOT_SUPPORTED;
			goto __exit_upgrade;
		}
		else if ((part_head->fota_algo & RT_FOTA_CMPRS_STAT_MASK) != RT_FOTA_CMPRS_ALGO_GZIP) 
		{
			log_d("GZIP not supported.")
			fota_err = RT_FOTA_ALGO_NOT_SUPPORTED;
			goto __exit_upgrade;
		}
		else
		{
			fota_err = rt_fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, RT_FOTA_ALGO_BUFF_SIZE);
			if (fota_err < 0)
			{
				log_d("AES256 algorithm failed.");
				fota_err = RT_FOTA_PART_READ_ERR;
				goto __exit_upgrade;
			}		
			fw_raw_pos += fota_err;

			if (rt_fota_write_app_part(total_copy_size, crypt_buf, fota_err) < 0)
			{
				fota_err = RT_FOTA_COPY_FAILED;
				goto __exit_upgrade;
			}
			
			total_copy_size += fota_err;
			rt_kprintf(">");
		}
	}

__exit_upgrade:
	if (aes_ctx)
		rt_free(aes_ctx);

	if (aes_iv)
		rt_free(aes_iv);

	if (crypt_buf)
		rt_free(crypt_buf);

	if (cmprs_buff)
		rt_free(cmprs_buff);

	if (dcprs_buff)
		rt_free(dcprs_buff);

	if (fota_err == RT_FOTA_NO_ERR)
	{
    	log_i("Upgrade success, total %d bytes.", total_copy_size);
	}
	return fota_err;
}

static int rt_fota_start_application(void)
{
	int fota_res = RT_FOTA_NO_ERR;
	const struct fal_partition *part;
	rt_uint32_t app_addr;

	part = fal_partition_find(fota_part_head.app_part_name);
	if (part == RT_NULL)
	{		
		log_d("Partition[%s] not found.", fota_part_head.app_part_name);
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}

	app_addr = part->offset + 0x08000000;
	//判断是否为0x08XXXXXX.
	if (((*(__IO uint32_t *)(app_addr + 4)) & 0xff000000) != 0x08000000)
	{
		log_d("Illegal Flash code.");
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}
	// 检查栈顶地址是否合法.
	if (((*(__IO uint32_t *)app_addr) & 0x2ffe0000) == 0x20000000)	
	{
		log_d("Illegal Stack code.");
		fota_res = RT_FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}

	log_i("Execute application now.");

	//用户代码区第二个字为程序开始地址(复位地址)
	app_func = (rt_fota_app_func)*(__IO uint32_t *)(app_addr + 4);
	/* Configure main stack */
	__set_MSP(app_addr);
	/* jump to application */
	app_func();

	log_i("Execute application failed.");
__exit_start_application:
	return fota_res;
}

void rt_boot_entry(void *arg)
{
	int fota_err = RT_FOTA_NO_ERR;

	rt_fota_print_log();

	fota_err = rt_fota_boot_verify();
	if (fota_err != RT_FOTA_NO_ERR)
		goto __exit_boot_entry;

	fota_err = rt_fota_part_fw_verify(RT_FOTA_FM_PART_NAME);
	if (fota_err != RT_FOTA_NO_ERR)
		goto __exit_boot_entry;

	if (rt_fota_check_upgrade() <= 0)
		goto __exit_boot_entry;

	fota_err = rt_fota_upgrade(RT_FOTA_FM_PART_NAME);
	if (fota_err != RT_FOTA_NO_ERR)
		goto __exit_boot_entry;

__exit_boot_entry:
	if (fota_err == RT_FOTA_NO_ERR)
	{		
		rt_fota_start_application();
	}

	log_i("Auto boot failed, Please switch manual boot.");
}

int main(void)
{
	rt_thread_t tid;

	tid = rt_thread_create("ra-boot", rt_boot_entry, RT_NULL, 4096, 8, 10);
	if (tid != RT_NULL)
	{
		rt_thread_startup(tid);
	}
	
    return RT_EOK;
}

