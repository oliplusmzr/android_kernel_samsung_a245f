############################################################################################################################################
1. How to Build
   - get Toolchain
     get the proper toolchain packages from AOSP or Samsung Open Source or ETC.

     (1) AOSP Kernel
         https://source.android.com/docs/setup/build/building-kernels
         $ repo init -u https://android.googlesource.com/kernel/manifest -b common-android14-6.1
         $ repo sync

     (2) Samsung Open Source
         https://opensource.samsung.com/uploadSearch?searchValue=toolchain

         copy the following list to the root directory
         - build/
         - external/
         - prebuilts/
         - tools/

   - Set Build Environment and Export Target Config
      $ cd kernel
      $ python kernel_device_modules-6.12/scripts/gen_build_config.py
                                            --kernel-defconfig mediatek-bazel_defconfig
                                            --kernel-defconfig-overlays "entry_level.config sec_ogki_fragment.config mt6789_disable_mtk_charger_overlay.config mt6789_teegris_4_overlay.config"
                                            --kernel-build-config-overlays ""
                                            -m user -o ../out/target/product/a24/obj/KERNEL_OBJ/build.config

      $ export DEVICE_MODULES_DIR="kernel_device_modules-6.12"
      $ export BUILD_CONFIG="../out/target/product/a24/obj/KERNEL_OBJ/build.config"
      $ export OUT_DIR="../out/target/product/a24/obj/KLEAF_OBJ"
      $ export DIST_DIR="../out/target/product/a24/obj/KLEAF_OBJ/dist"
      $ export DEFCONFIG_OVERLAYS="entry_level.config sec_ogki_fragment.config mt6789_disable_mtk_charger_overlay.config mt6789_teegris_4_overlay.config"
      $ export PROJECT="mgk_64_k612"
      $ export MODE="user"

   - To Build
      $ ./kernel_device_modules-6.12/build.sh

2. Output Files
   - Kernel : out/target/product/a24/obj/KLEAF_OBJ/dist/kernel_device_modules-6.12/mgk_64_k612_kernel_aarch64.user/Image.gz
   - Module : out/target/product/a24/obj/KLEAF_OBJ/dist/*/*.ko
############################################################################################################################################
