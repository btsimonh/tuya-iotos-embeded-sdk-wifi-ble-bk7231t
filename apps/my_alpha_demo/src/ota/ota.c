#include "typedef.h"
#include "flash_pub.h"
#include "../logging/logging.h"


static unsigned char *sector = (void *)0;
int sectorlen = 0;
unsigned int addr = 0xff000;
#define SECTOR_SIZE 0x1000
static void store_sector(unsigned int addr, unsigned char *data);

int init_ota(startaddr){
    flash_init();
	flash_protection_op(FLASH_XTX_16M_SR_WRITE_ENABLE, FLASH_PROTECT_NONE);
    if (startaddr > 0xff000){
        if (sector){
            addLog("aborting OTS, sector already non-null\n");
            return 0;
        }
        sector = os_malloc(SECTOR_SIZE);
        sectorlen = 0;
        addr = startaddr;
        addLog("init OTS, strataddr 0x%x\n", startaddr);
        return 1;
    } 
    addLog("aborting OTA, startaddr 0x%x < 0xff000\n", startaddr);
    return 0;
}

void close_ota(){
    if (sectorlen){
        addLog("close OTA, additional 0x%x FF added \n", SECTOR_SIZE - sectorlen);
        memset(sector+sectorlen, 0xff, SECTOR_SIZE - sectorlen);
        sectorlen = SECTOR_SIZE;
        store_sector(addr, sector);
        addr += 1024;
        sectorlen = 0;
    }
    addLog("close OTA, addr 0x%x\n", addr);

    os_free(sector);
    sector = (void *)0;
	flash_protection_op(FLASH_XTX_16M_SR_WRITE_ENABLE, FLASH_UNPROTECT_LAST_BLOCK);
}

void add_otadata(unsigned char *data, int len){
    if (!sector) return;
    addLog("OTA DataRxed start: %02.2x %02.2x len %d\r\n", data[0], data[1], len);

    while (len){
        if (sectorlen < SECTOR_SIZE){
            int lenstore = SECTOR_SIZE - sectorlen;
            if (lenstore > len) lenstore = len;
            memcpy(sector + sectorlen, data, lenstore);
            data += lenstore;
            len -= lenstore;
            sectorlen += lenstore;
            addLog("OTA sector start: %02.2x %02.2x len %d\r\n", sector[0], sector[1], sectorlen);
        }

        if (sectorlen == SECTOR_SIZE){
            store_sector(addr, sector);
            addr += SECTOR_SIZE;
            sectorlen = 0;
        } else {
            addLog("OTA sectorlen 0x%x not yet 0x%x\n", sectorlen, SECTOR_SIZE);
        }
    }
}

static void store_sector(unsigned int addr, unsigned char *data){
    addLog("writing OTA, addr 0x%x\n", addr);
    flash_ctrl(CMD_FLASH_WRITE_ENABLE, (void *)0);
    flash_ctrl(CMD_FLASH_ERASE_SECTOR, &addr);
    flash_ctrl(CMD_FLASH_WRITE_ENABLE, (void *)0);
    flash_write(data , SECTOR_SIZE, addr);
}