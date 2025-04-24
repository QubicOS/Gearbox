/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <sys/errno.h>
#include "esp_idf_version.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp32s2/rom/cache.h"
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5,0,0)
#include "esp32s2/spiram.h"
#endif
#include "soc/mmu.h"
#include "private/elf_platform.h"

#define TAG "ELF_MMU"

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5,0,0)
#define PSRAM_VADDR_START   0x3F800000
#else
#define PSRAM_VADDR_START   (DRAM0_CACHE_ADDRESS_HIGH - esp_spiram_get_size())
#endif

#define MMU_INVALID_ENTRY  BIT(14)
#define MMU_UNIT_BYTES     0x10000
#define MMU_REG_BASE       ((volatile uint32_t *)DR_REG_MMU_TABLE)

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5,2,0)
#define IRAM_LOW_ADDR      SOC_IRAM0_ADDRESS_LOW
#define IRAM_HIGH_ADDR     SOC_IRAM0_ADDRESS_HIGH
#define MMU_SPIRAM_FLAG    SOC_MMU_ACCESS_SPIRAM
#else
#error "Unsupported ESP-IDF version"
#endif

#define IBUS_BASE_ADDR     IRAM_LOW_ADDR
#define IBUS_MAX_SLOTS     ((IRAM_HIGH_ADDR - IRAM_LOW_ADDR) / MMU_UNIT_BYTES)
#define IBUS_START_SLOT    8

#define SECS_FROM_SIZE(sz) (((sz) + MMU_UNIT_BYTES - 1) / MMU_UNIT_BYTES)
#define PSRAM_OFFSET(addr) (((uintptr_t)(addr)) - PSRAM_VADDR_START)
#define PSRAM_SECS(addr)   SECS_FROM_SIZE(PSRAM_OFFSET(addr))
#define PSRAM_ALIGN_DOWN(addr) ((uintptr_t)(addr) & ~(MMU_UNIT_BYTES - 1))
#define ICACHE_ADDR(slot)  (IBUS_BASE_ADDR + (slot) * MMU_UNIT_BYTES)

/**
 * @brief Find a contiguous block of free IBus MMU slots.
 *
 * @param slots_needed Number of slots required.
 * @return Slot index on success, -1 if not found.
 */
static int find_free_ibus_slot(int slots_needed)
{
    volatile uint32_t *mmu = MMU_REG_BASE;
    for (int slot = IBUS_START_SLOT; slot < IBUS_MAX_SLOTS; ++slot) {
        if (mmu[slot] != MMU_INVALID_ENTRY) {
            continue;
        }
        int count = 1;
        while (count < slots_needed && (slot + count) < IBUS_MAX_SLOTS
               && mmu[slot + count] == MMU_INVALID_ENTRY) {
            ++count;
        }
        if (count >= slots_needed) {
            return slot;
        }
    }
    return -1;
}

/**
 * @brief Map PSRAM pages into ICache MMU.
 *
 * @param first_slot Starting slot index.
 * @param psram_start_ps Page offset in PSRAM (in MMU units).
 * @param slots_needed Number of slots to map.
 */
static void map_psram_to_icache(int first_slot, uint32_t psram_start_ps, int slots_needed)
{
    volatile uint32_t *mmu = MMU_REG_BASE;
    assert(first_slot >= 0 && (first_slot + slots_needed) <= IBUS_MAX_SLOTS);

    for (int i = 0; i < slots_needed; ++i) {
        mmu[first_slot + i] = MMU_SPIRAM_FLAG | (psram_start_ps + i);
    }
}

/**
 * @brief Unmap IBus MMU slots.
 *
 * @param first_slot Starting slot index.
 * @param slots_count Number of slots to clear.
 */
static void unmap_ibus_slots(int first_slot, int slots_count)
{
    volatile uint32_t *mmu = MMU_REG_BASE;
    assert(first_slot >= 0 && (first_slot + slots_count) <= IBUS_MAX_SLOTS);

    for (int i = 0; i < slots_count; ++i) {
        mmu[first_slot + i] = MMU_INVALID_ENTRY;
    }
}

/**
 * @brief Initialize MMU for ELF text in PSRAM.
 *
 * @param elf ELF context with text section info.
 * @return ESP_OK on success, error code otherwise.
 */
esp_err_t IRAM_ATTR esp_elf_arch_init_mmu(esp_elf_t *elf)
{
    if (elf == NULL || elf->sec == NULL) {
        ESP_LOGE(TAG, "Invalid ELF context");
        return ESP_ERR_INVALID_ARG;
    }

    const esp_elf_sec_t *text_sec = &elf->sec[ELF_SEC_TEXT];
    size_t text_sz = text_sec->size;
    uint32_t psram_offset = PSRAM_SECS(elf->ptext);
    int slots = SECS_FROM_SIZE(text_sz);

    spi_flash_disable_interrupts_caches_and_other_cpu();
    int slot_idx = find_free_ibus_slot(slots);
    if (slot_idx < 0) {
        spi_flash_enable_interrupts_caches_and_other_cpu();
        ESP_LOGE(TAG, "No contiguous %d MMU slots available", slots);
        return ESP_ERR_NO_MEM;
    }

    map_psram_to_icache(slot_idx, psram_offset, slots);
    spi_flash_enable_interrupts_caches_and_other_cpu();

    elf->mmu_off = slot_idx;
    elf->mmu_num = slots;
    elf->text_off = ICACHE_ADDR(slot_idx) - PSRAM_ALIGN_DOWN(elf->ptext);

    ESP_LOGD(TAG, "Mapped %d pages at slot %d, text off 0x%08x",
             slots, slot_idx, elf->text_off);

    return ESP_OK;
}

/**
 * @brief Deinitialize MMU mapping for ELF text.
 *
 * @param elf ELF context previously initialized.
 */
void IRAM_ATTR esp_elf_arch_deinit_mmu(esp_elf_t *elf)
{
    if (elf == NULL || elf->mmu_off < 0 || elf->mmu_num <= 0) {
        ESP_LOGW(TAG, "Invalid or uninitialized MMU mapping");
        return;
    }

    spi_flash_disable_interrupts_caches_and_other_cpu();
    unmap_ibus_slots(elf->mmu_off, elf->mmu_num);
    spi_flash_enable_interrupts_caches_and_other_cpu();

    ESP_LOGD(TAG, "Unmapped %d MMU slots at %d", elf->mmu_num, elf->mmu_off);

    elf->mmu_off = -1;
    elf->mmu_num = 0;
    elf->text_off = 0;
}
