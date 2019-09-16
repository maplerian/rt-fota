# FAL模块的添加和使用

## 初次添加FAL模块到工程中 (1st@spunky:2019/9/3)

### 1.在menuconfig中下载与配置fal模块

+ env命令行中输入命令

```bash
> menuconfig
```

+ 找到FAL模块所在目录进行选择和配置

```bash
RT-Thread online packages
    system packages --->
        --- fal: Flash Abstraction Layer implement. Manage flash device and partition.
        [*]   Enable debug log output
        [*]   FAL partition table config has defined on 'fal_cfg.h'
        [*]   FAL uses SFUD drivers
        (nor_flash0) The name of the device used by FAL (NEW)
                version (latest)  --->
```

+ 退出配置菜单并在env命令行中输入命令

```bash
> pkgs --update
```

### 2.修改FAL模块的移植文件

FAL模块的移植文件有3个,根据目标板实际情况进行修改

- fal_cfg.h: 配置FAL模块管理的分区信息和相关宏定义

```c
#define NOR_FLASH_SPI_DEV_NAME             "nor_spi"    /* 定义操作NOR flash的SPI设备 */

/* 这些宏定义了STM32F4系列单片机内部FLASH页面信息, 用于drv_flash_f4.c中的操作函数 */
#define STM32_FLASH_START_ADRESS_16K       ((uint32_t)0x08000000) /* Base @ of Sector 0, 16 Kbytes */
#define FLASH_SIZE_GRANULARITY_16K            (4 * 16 * 1024)

#define STM32_FLASH_START_ADRESS_64K       ((uint32_t)0x08010000) /* Base @ of Sector 4, 64 Kbytes */
#define FLASH_SIZE_GRANULARITY_64K            (1 * 64 * 1024)

#define STM32_FLASH_START_ADRESS_128K      ((uint32_t)0x08020000) /* Base @ of Sector 5, 128 Kbytes */
#define FLASH_SIZE_GRANULARITY_128K            (7 * 128 * 1024)

/* 定义FAL模块所需要使用的FLASH设备列表, 这些FLASH设备定义了设备信息和操作函数 */
extern const struct fal_flash_dev stm32f4_onchip_flash;
extern struct fal_flash_dev nor_flash0;

/* flash device table */
#define FAL_FLASH_DEV_TABLE                                          \
{                                                                    \
    &stm32f4_onchip_flash,                                           \
    &nor_flash0,                                                     \
}

/* 定义分区表信息, 如果要上bootloader配置, 此处可以不设置 */
#ifdef FAL_PART_HAS_TABLE_CFG
/* partition table */
#define FAL_PART_TABLE                                                               \
{                                                                                    \
    {FAL_PART_MAGIC_WROD, "app",  "onchip_flash", 0,                1024 * 1024, 0}, \
    {FAL_PART_MAGIC_WROD, "para",  "nor_flash",   0,                1024 * 1024, 0}, \
    {FAL_PART_MAGIC_WROD, "image", "nor_flash",   1024 * 1024,      1024 * 1024, 0}, \
    {FAL_PART_MAGIC_WROD, "dl",    "nor_flash",   (1024 + 1024) * 1024, 1024 * 1024, 0}, \
    {FAL_PART_MAGIC_WROD, "elmfs", "nor_flash",   (1024 + 1024 + 1024) * 1024, 13 * 1024 * 1024, 0}, \
}
#endif /* FAL_PART_HAS_TABLE_CFG */
```

- fal_flash_sfud_port.c: 移植sfud驱动相关操作函数, 必须使能RT_USING_SFUD宏定义

  FAL_USING_NOR_FLASH_DEV_NAME是SFUD驱动类型的FLASH设备名---“nor_flash0”, 系统上电启动后自动执行sfud_nor_flash_init()函数, 将“nor_flash”粘附在SPI设备"nor_spi上"

```c
int sfud_nor_flash_init(void)
{
    const struct pin_index *cs_pin;

    extern const struct pin_index *get_pin(uint8_t pin);

    cs_pin = get_pin(BSP_DATAFALSH_CS_PIN);
    if (cs_pin != RT_NULL)
    {
        rt_hw_spi_device_attach("spi1", NOR_FLASH_SPI_DEV_NAME, cs_pin->gpio, cs_pin->pin);
        if (rt_sfud_flash_probe(FAL_USING_NOR_FLASH_DEV_NAME, NOR_FLASH_SPI_DEV_NAME) == RT_NULL)
        {
            return -RT_ERROR;
        }
        return RT_EOK;
    }

    return -RT_ERROR;
}
INIT_DEVICE_EXPORT(sfud_nor_flash_init);
```

- fal_flash_stm32f4_port.c: 移植stm32单片机内部flash驱动相关操作函数, 不同系列的MCU其操作方式不一样

- 在env命令行中输入命令

```c
> scons --target=mdk5
```

### 3.在main.c中启动FAL模块的初始化

```c
int fs_init(void)
{
    /* partition initialized FAL模块初始化:检查分区正确性和初始化 */
    fal_init();
    /* easyflash initialized */
    easyflash_init();

    /* Create a block device on the file system partition of spi flash */
    struct rt_device *flash_dev = fal_blk_device_create(FS_PARTITION_NAME);
    if (flash_dev == RT_NULL)
    {
        LOG_D("Can't create a block device on '%s' partition.", FS_PARTITION_NAME);
    }
    else
    {
        LOG_D("Create a block device on the %s partition of flash successful.", FS_PARTITION_NAME);
    }

    /* mount the file system from "filesystem" partition of spi flash. */
    if (dfs_mount(FS_PARTITION_NAME, "/", "elm", 0, 0) == 0)
    {
        LOG_D("Filesystem initialized!");
    }
    else
    {
        LOG_D("Failed to initialize filesystem!\n");
        LOG_D("You should create a filesystem on the block device first!");
        LOG_D("msh> mkfs -t elm %s", FAL_USING_NOR_FLASH_DEV_NAME);
    }    

    return 0;
}
INIT_ENV_EXPORT(fs_init);
```
