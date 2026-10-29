# Live Sensors: published limits, sources, and default alert thresholds

Research notes for the default alert thresholds on the Live Sensors page (LibreHardwareMonitor).
Researched 2026-10-29. Part 1 is what sources say. Part 2 is a recommendation derived from them, not a published value.

Verification key: **(F)** the page was opened and the number read directly. **(S)** the number came from a search-result excerpt of that page and was not opened.

## 1. Published numbers and sources

### Intel CPU
- Tjunction max "usually is between 100°C-110°C". Intel does "not provide typical temperature operating ranges". Running at max temperature under load "isn't necessarily cause for concern" because the chip throttles, then shuts down to protect itself. (F)
  Source: [Intel support article 000005597](https://www.intel.com/content/www/us/en/support/articles/000005597/processors.html)
- Core i9-14900K: T Junction 100°C, Max Operating Temperature 100°C. (F)
  Source: [Intel ARK, Core i9-14900K](https://www.intel.com/content/www/us/en/products/sku/236773/intel-core-i9-processor-14900k-36m-cache-up-to-6-00-ghz/specifications.html)

### AMD CPU
- Ryzen 7 9700X: Max. Operating Temperature (Tjmax) 95°C. (F)
  Source: [AMD Ryzen 7 9700X product page](https://www.amd.com/en/products/processors/desktops/ryzen/9000-series/amd-ryzen-7-9700x.html)

### NVIDIA GPU
- RTX 4070, 4070 SUPER, 4070 Ti, 4070 Ti SUPER: Maximum GPU Temperature 90°C (reference/Founders Edition designs). (F)
  Source: [NVIDIA GeForce RTX 4070 family](https://www.nvidia.com/en-us/geforce/graphics-cards/40-series/rtx-4070-family/)

### AMD GPU
- RX 7900 series: an AMD support reply says the cards "can operate up to 110 degree Celsius Junction temperature... within spec". This is a community-thread reply, not a formal spec page. (S)
  Source: [AMD community thread](https://community.amd.com/t5/graphics-cards/reference-7900-xtx-110c-junction-temp-and-maxed-fan-speed-on/td-p/568578)
- No official AMD edge-temperature limit was found.

### Storage
- Samsung 990 PRO NVMe: operating 0°C to 70°C, measured by S.M.A.R.T. temperature. (S)
  Source: [Samsung 990 PRO datasheet](https://download.semiconductor.samsung.com/resources/data-sheet/Samsung_NVMe_SSD_990_PRO_Datasheet_Rev.1.0_10129514051890.pdf)
- Seagate BarraCuda 3.5" HDD: operating 0°C minimum, 60°C maximum at the drive case. (S)
  Source: [Seagate BarraCuda 3.5" datasheet](https://www.seagate.com/content/dam/seagate/en/content-fragments/products/datasheets/barracuda-3-5/3-5-barracudaDS2131-3-US2501-en_US.pdf)
- Seagate BarraCuda 2.5" HDD: operating 0°C to 60°C. (S)
  Source: [Seagate BarraCuda 2.5" datasheet](https://www.seagate.com/content/dam/seagate/migrated-assets/www-content/datasheets/pdfs/barracuda-2-5-DS1907-3-2005US-en_US.pdf)

### Fans
- Noctua NF-A12x25 PWM: 2000 RPM (±10%) maximum, 450 RPM (±20%) minimum at 20% PWM, 0 RPM at 0% PWM (stops by design). (S; the page blocked a direct fetch)
  Source: [Noctua NF-A12x25 PWM specification](https://noctua.at/en/nf-a12x25-pwm/specification)
- No universal minimum or maximum fan RPM is published. Values vary by model.

### Motherboard, chipset, VRM
- No clear published guidance found (ASUS, MSI, Gigabyte limits were not found).

### Not yet sourced
Core Ultra CPUs, mid-range Intel Core i5/i7, Intel Arc GPUs, other AMD GPUs, WD and Crucial drives, stock coolers, Intel/AMD chipset datasheets, and DDR4/DDR5 (JEDEC) memory limits.

## 2. Recommended default thresholds

These are recommendations derived from the numbers above. Where noted, they are heuristics with no published source and must be user-adjustable.

| Component | Warning | Critical | Basis |
|---|---|---|---|
| Intel CPU (package/core) | about 90°C (Tjunction minus 10) | about 98°C (Tjunction minus 2), only if sustained 30 s or more | Tjunction 100°C on the 14900K. Intel says brief hits at max are normal, so alert on sustained heat. Prefer reading each chip's own Tjunction and use fixed values only as a fallback. |
| AMD CPU (Tctl/Tdie) | 85°C | 93°C, sustained | Tjmax 95°C on the 9700X. Ryzen boosts up to that limit by design. |
| NVIDIA GPU core | 83°C | 88°C | Published maximum 90°C. |
| AMD GPU junction/hotspot | 100°C | 108°C | AMD support: up to 110°C junction in spec (informal source). Skip edge-temperature alerts (no published limit), or reuse the NVIDIA values. |
| NVMe / SSD | 65°C | 70°C | Samsung 990 PRO operating maximum 70°C (SMART temperature). |
| HDD | 50°C | 58°C | Seagate BarraCuda case maximum 60°C, little headroom. |
| Motherboard / chipset | 70°C | 80°C | Heuristic, no published limit. User-adjustable. |
| VRM | 90°C | 105°C | Heuristic, no published limit. User-adjustable. |
| Fan RPM | below about 300 RPM while temperatures are rising | 0 RPM, only when the related temperature is above its warning level (a stall) | No universal RPM threshold exists, and many fans stop at 0% PWM by design. |
