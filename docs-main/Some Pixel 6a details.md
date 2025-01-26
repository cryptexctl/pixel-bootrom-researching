
# Содержимое образа:

1.ufs: Два небольших блока данных размером 0xC5 (197 байт) каждый.

2.partition: Четыре небольших блока, вероятно, связанных с таблицей разделов или метаданными.

3.bl1: Блок данных размером 0x3000 (12 KB), содержащий загрузчик BL1.

4.pbl: Блок данных размером 0xC000 (48 KB), содержащий Primary Boot Loader.

5.bl2: Вторичный загрузчик BL2, размером 0x85000 (532 KB).

6.abl: Раздел с ABL (Android Bootloader), размером 0x1D9000 (1.81 MB).

7.bl31: Блок Trusted Firmware (BL31), размером 0x16000 (88 KB).

8.tzsw: Раздел TZSW (TrustZone Software), размером 0x48D000 (4.72 MB).

9.gsa: Раздел GSA (Generic Secure Architecture), размером 0x40000 (256 KB).

10.ldfw: Раздел LDFW (Load Firmware), размером 0x3E8000 (3.9 MB).

11.ufsfwupdate: Очень маленький раздел (84 байта), вероятно, связанный с обновлением UFS.

# **Что важно в выводе:**

1. APBL

Это может быть аббревиатура для “Application Boot Loader” или “Primary Boot Loader”.

Указывает на связь с первыми этапами загрузки устройства.

2. WHITECHAPEL

Это кодовое имя или внутренний проект, связанный с процессором. Например, Whitechapel известно как кодовое название Google Tensor SoC.

Подтверждает, что загрузчик предназначен для устройства с этим чипом.

3. EPBL **и** DPM1

EPBL: Вероятно, “Extended Primary Boot Loader”.

DPM1: Может быть связан с “Device Power Management” или подобной функцией, связанной с управлением питанием.

4. **Произвольные строки**

Множество строк выглядят как потенциальные инструкции, адреса или таблицы данных. Это может быть частью машинного кода, исполняемого на этапе загрузки.

###### Понимая последовательность запуска (boot chain), можно сосредоточиться на ключевых элементах каждого этапа, чтобы искать следы бутрома:

1. bl1 **(Boot Loader 1)**:

**Основная задача: Инициализация минимального набора оборудования и передача управления PBL.**

_Ищем:_

>Таблицы секторов или сигнатуры, указывающие на загрузочные данные.

>Инструкции перехода (Branch) на PBL.

>Векторы сброса или базовые точки входа.

2. pbl **(Primary Boot Loader)**:

**Основная задача: Настройка основного оборудования (например, памяти и контроллеров).**

_Ищем:_

> Таблицы с параметрами памяти (например, DDR).

> Метаданные о разделах.

> Адреса, откуда PBL загружает следующий этап (BL2).

3. bl2 **(Boot Loader 2)**:

**Основная задача: Загрузка и проверка ABL.**

 _Ищем:

>Коды проверки целостности (например, HMAC или CRC).

>Указатели на загрузку ABL.

> Маркеры, подтверждающие аутентификацию компонентов (если применимо).

4. abl **(Android Boot Loader)**:

 Основная задача: Загрузка ядра Android.

_Ищем:_

>Образы ядра и ramdisk.

>Указания на доверенные компоненты (например, TZ или GSA).

> Адреса передачи управления на BL31.

5. bl31 **(Trusted Firmware)**:

> Основная задача: Настройка TrustZone и управление переходами между уровнями привилегий.

> Ищем:

> Secure Monitor Calls (SMC).

> Конфигурацию TrustZone.

> Метаданные о безопасных областях памяти.

6. gsa **(Generic Secure Architecture)**:

> Основная задача: Включение механизмов безопасности (например, криптографических модулей).

> Ищем:

> Криптографические ключи или инициализацию.

> Структуры проверки загрузки.

7. trusty **(если есть)**:

> Основная задача: Выполнение доверенных операций в TrustZone.

> Ищем:

> API TrustyOS.

> Таблицы или данные управления безопасными приложениями.

8. ldfw **(Load Firmware)**:

> Основная задача: Загрузка прошивки для периферийных устройств.

> Ищем:

> Таблицы устройств.

> Указания на загрузку периферийных компонентов.


### Trusty (следы трости):
```
arbung@MacBook-Air-romanticunchanging extracted % strings * | grep -i "trusty"
Trusty Abort
trusty_ipc_dev_create
external/lib/trusty/ql-tipc/trusty_dev_common.c
trusty_ipc_send
trusty_ipc_dev_send
Trusty device should be initialized before connecting to hwbcc.
external/lib/trusty/ql-tipc/keymaster.c
selected trusty api version: %u (requested %u)
trusty_ipc_recv
trusty_ipc_dev_close
%s: failed (%d) to shutdown Trusty IPC device
trusty_ipc_dev_shutdown
trusty_ipc_dev_recv
[%4llu.%06llu] [E] [BCC] Trusty hwbcc init failed.
Trusty device should be initialized before connecting to keymint.
trusty_ipc_poll_for_event
external/lib/trusty/ql-tipc/ipc_dev.c
trusty_ipc_dev_connect
Failed to create trusty ipc device: %d
external/lib/trusty/ql-tipc/ipc.c
trusty_ipc_connect
Failed to shut down trusty device: %d
It is unsafe to boot with a trusty device still open, dying.
Failed to initialize trusty device: %d
[%4llu.%06llu] [E] [BCC] Trusty device init failed.
[%4llu.%06llu] [E] [AVB] trusty_km_init failed
[%4llu.%06llu] [W] [AVB] trusty_set_boot_patchlevel failed
%s: failed to allocate Trusty IPC device
[%4llu.%06llu] [E] [AVB] trusty_init failed
lib/pixel/trusty/mgmt.c
com.android.trusty.hwbcc
%s: failed (%d) to create Trusty IPC device
trusty_ipc_dev_get_event
external/lib/trusty/ql-tipc/arch/arm/trusty_mem.c
external/lib/trusty/ql-tipc/hwbcc.c
unsupported trusty api version %u > %u
com.android.trusty.keymaster
trusty_init
trusty_km_init
trusty_km_shutdown
trusty_hwbcc_init
trusty_hwbcc_shutdown
trusty_shutdown
trusty_idle
trusty_lock
trusty_unlock
trusty_local_irq_disable
trusty_local_irq_restore
trusty_abort
trusty_printf
trusty_memcpy
trusty_memset
trusty_strcpy
trusty_strlen
trusty_calloc
trusty_free
trusty_alloc_pages
trusty_free_pages
trusty_ipc_chan_init
trusty_ipc_connect
trusty_ipc_close
trusty_ipc_send
trusty_ipc_recv
trusty_ipc_poll_for_event
trusty_ipc_dev_create
trusty_ipc_dev_shutdown
trusty_ipc_dev_connect
trusty_ipc_dev_close
trusty_ipc_dev_get_event
trusty_ipc_dev_send
trusty_ipc_dev_recv
trusty_ipc_dev_idle
trusty_dev_init_ipc
trusty_dev_exec_ipc
trusty_dev_shutdown_ipc
trusty_dev_init
trusty_dev_shutdown
trusty_basename
trusty_set_boot_params
trusty_set_boot_patchlevel
trusty_encode_page_info
trusty/kernel/lib/trusty/include/lib/trusty/trusty_app.h
trusty/kernel/lib/trusty/trusty_app.c
trusty_app_create: ELF header out of bounds
trusty_app: failed to allocate memory for trusty app
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/pm.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/sysram/sysram.c
trusty/kernel/lib/trusty/event.c
trusty/hardware/google/whitechapel/gsa/dev/mbox/mbox.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/ssmt/ssmt.c
int trusty_app_symbolize(struct trusty_app *, uintptr_t, struct pc_symbol_info *)
libtrusty_apps
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/alive/alive.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/pmu/pmu.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/cmu/cmu.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/slc/slc.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/sss.c
trusty_app_%d_%08x-%04x-%04x
trusty/kernel/lib/trusty/handle_set.c
trusty/kernel/lib/trusty/ipc.c
failed to load trusty_app: trusty_app heap creation error
failed to allocate trusty thread for %s
trusty/hardware/google/whitechapel/gsa/dev/dma/pl330/pl330.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/gme/gme.c
libtrusty
trusty_app_create: ELF header not found
trusty/kernel/lib/trusty/uctx.c
initializing trusty (%s)
void trusty_app_exit(int)
trusty_thread
trusty/kernel/lib/trusty/uirq.c
trusty/hardware/google/whitechapel/gsa/lib/trusty-gsa/tipc_bridge.c
status_t alloc_address_map(struct trusty_app *)
trusty/user/whitechapel/gsa/app/hwcrypto/hwcrypto-kdn.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/user/sss-aes.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/user/sss-rng.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/user/sss-rsa.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/user/sss-user.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/hardware/google/whitechapel/gsa/dev/crypto/sss/user/sss-hash.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/whitechapel/gsa/app/hwcrypto/hwcrypto-srv.c
trusty/user/whitechapel/gsa/lib/gscproxy/client/client.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/sjtag/user/sjtag-user.c
trusty/user/whitechapel/gsa/app/hwmgr/sjtag-srv.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/user/whitechapel/gsa/app/hwmgr/tpu-image.c
trusty/user/whitechapel/gsa/app/hwmgr/aoc-image.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/otp/user/otp-user.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/whitechapel/gsa/app/hwmgr/image-auth-srv.c
trusty/hardware/google/whitechapel/gsa/dev/mbox/user/mbox-user.c
trusty/user/whitechapel/gsa/app/hwmgr/fwmgr-common.c
trusty/user/whitechapel/gsa/lib/gscproxy/srv/gscproxy-srv.c
trusty/user/base/lib/libc-trusty/time.c
trusty/user/whitechapel/gsa/app/gscproxy/nos-call.c
trusty/user/whitechapel/gsa/app/gscproxy/spi-transport.c
trusty_nanosleep
trusty/user/base/lib/tipc/tipc_srv.c
trusty/hardware/google/whitechapel/common/dev/usi/user/spi/spi-user.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/user/whitechapel/gsa/app/kdn/kdn-srv.c
trusty/user/base/lib/tipc/tipc.c
trusty/kernel/services/apploader/apploader_service.c
trusty/kernel/lib/trusty/include/lib/trusty/trusty_app.h
trusty/kernel/lib/trusty/trusty_app.c
trusty_app_create: ELF header out of bounds
trusty_smcall
trusty_app: failed to allocate memory for trusty app
void trusty_sm_init(uint)
%s:%d: %s: error (%d) allocating struct trusty_app_img
int on_ta_shutdown(struct trusty_app *)
trusty/kernel/lib/trusty/event.c
com.android.trusty.kernel.handle_prot
trusty/kernel/lib/sm/shared_mem.c
trusty/hardware/google/whitechapel/gsa/platform/whi-gsa/dev/ssmt/ssmt.c
trusty error register entity: %d
trusty/kernel/lib/metrics/metrics.c
int trusty_app_symbolize(struct trusty_app *, uintptr_t, struct pc_symbol_info *)
void thread_service_setaffinity_cb(struct trusty_app *, void *)
libtrusty_apps
trusty_app_%d_%08x-%04x-%04x
void thread_service_getaffinity_cb(struct trusty_app *, void *)
trusty/kernel/lib/trusty/handle_set.c
trusty/kernel/lib/trusty/ipc.c
trusty/kernel/lib/trusty/ipc_msg.c
trusty/kernel/lib/trusty/tipc_virtio_dev.c
failed to load trusty_app: trusty_app heap creation error
%s:%d: %s: overflow when computing trusty_app pointers
int report_crash(struct handle *, struct trusty_app *)
failed to allocate trusty thread for %s
%s:%d: %s: error (%d) creating Trusty app
trusty/hardware/google/whitechapel/gsa/dev/dma/pl330/pl330.c
libtrusty
trusty_app_create: ELF header not found
trusty/kernel/lib/trusty/uctx.c
trusty/hardware/google/whitechapel/tz/services/fp_spi_dma/fp_spi_dma_service.c
trusty/kernel/lib/sm/sm.c
com.android.trusty.metrics.consumer
initializing trusty (%s)
void trusty_app_exit(int)
trusty/kernel/lib/trusty/tipc_dev_ql.c
trusty_thread
trusty/kernel/lib/trusty/uirq.c
trusty/hardware/google/whitechapel/common/dev/usi/usi_spi.c
status_t alloc_address_map(struct trusty_app *)
com.android.trusty.kernel.fp_spi_dma.
trusty/user/base/lib/secure_fb/secure_fb.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/afloader.c
external/trusty/musl/src/stdlib/qsort.c
com.android.trusty.kernel.cdt
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.secure_fb
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/afcjk.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/teeui/libteeui/include/teeui/utils.h
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/base/ftobjs.c
trusty/user/base/lib/tipc/tipc_srv.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/afmodule.c
trusty/user/app/confirmationui/src/main.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/aflatin.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/teeui/libteeui/include/teeui/generic_operation.h
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/afwarp.c
trusty/user/app/confirmationui/src/secure_input_tracker.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/raster/ftraster.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/smooth/ftgrays.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/teeui/libteeui/prebuilt/localization/ConfirmationUITranslations.cpp
trusty/kernel/lib/ubsan/ubsan.c
com.android.trusty.confirmationui
trusty/user/base/lib/tipc/tipc.c
com.android.trusty.hwrng
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/autofit/afglobal.c
com.android.trusty.keymaster.secure
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/external/freetype/src/truetype/ttinterp.c
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.hwkey
com.android.trusty.gatekeeper
trusty/kernel/lib/ubsan/ubsan.c
trusty_gatekeeper
com.android.trusty.storage.client.tp
com.android.trusty.hwrng
trusty/user/base/lib/storage/storage.c
com.android.trusty.keymaster.secure
TrustyGateKeeperDerivationData0
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 881: BoringSSL self-test: PASSED
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 84: error event (0x%x) for port (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 412: Dispatching IMPORT_KEY, size: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 666: Decrypting blob with format: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/auth_encrypted_key_blob.cpp, Line 309: Invalid key blob format %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 477: Wrote new factory reset secret.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/cppcose/cppcose.cpp
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 98: Failed to open secure storage session.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 422: Dispatching GET_VERSION, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 475: Dispatching ABORT_OPERATION, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 510: Dispatching IMPORT_WRAPPED_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 557: Dispatching KM_ATAP_SET_CA_RESPONSE_UPDATE, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 289: Found usage count limit tag: %u
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/include/keymaster/keymaster_utils.h, Line 68: KmErrorOr not checked
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/auth_encrypted_key_blob.cpp, Line 331: Invalid key blob format %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 565: Didn't find a slot and can't grow the file larger than %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 506: Auth required but no auth type found
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 471: Failed to validate and extract the endpoint encryption key.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 82: Failed to validate EEK chain: %s
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 277: Setting notBefore to %ld: 
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 133: Digest %d not supported
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 535: Dispatching SET_ATTESTATION_IDS, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1394: UnwrapKey:Done
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/ocb_utils.cpp, Line 136: Error %d while encrypting key
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 457: Failed to grow new file from 0 to %llu bytes
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 542: Opened session to store secure deletion secret.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 547: Failed to open file in CreateDateForNewKey
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 633: Failed to open session to get secure deletion data.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_operation.cpp, Line 66: %d digests found in HMAC key authorizations; must be exactly 1
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 99: Fail to read product id from storage, set as 0.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 427: Dispatching GET_VERSION_2, size: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 460: Failed to get secure deletion data. storageproxy not up?
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1177: Failed to parse wrapping key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/ocb_utils.cpp, Line 174: Failed to decrypt key, error: %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 142: Failed to update buffer write position. Code error.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 303: Error (%d) deleting file %s
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ckdf.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 420: Usage-count limited keys table not allocated.  Count-limited keys disabled
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 472: Auth token signature invalid
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 479: Failed to derive the session key.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 103: Key is missing required label 'PUBKEY_X'
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 398: Error: [%d] decoding from file '%s'
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 726: error: no context on channel %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/serializable.cpp
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 526: Failed to create secure deletion secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 126: Error memory allocation failed trying to allocate ReadBlock buffer.
trusty/user/app/keymaster/openssl_keymaster_enforcement.cpp, Line 247: Getting KAK failed.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 72: Error parsing EEK chain: %s
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 156: Error: [%d] Failed to sign the MAC key on WHI
trusty/user/base/lib/hwbcc/client/hwbcc.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 66: Invalid public exponent specified for RSA key generation
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 887: failed (%d) to initialize keymaster
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 525: Dispatching SET_BOOT_PARAMS, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 251: Error serializing response: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 269: do_dispatch #3 err: %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 708: Failed to commit transaction deleting key at slot %u
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 173: Error signing MAC: %s
trusty/user/app/keymaster/trusty_keymaster_enforcement.cpp, Line 69: Error %d computing token signature
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 79: Error deriving key
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 335: Did not receive full CA Response message: %d / %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 696: Read %d-byte message
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 591: Destroy attestation IDs is unimplemented.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 600: Dispatching KM_DEVICE_LOCKED, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 215: do_dispatch #1: serialized response, %d bytes
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 217: Error serializing response: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 104: Creating TrustyKeymaster
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 540: Upgrading rollback-protected key blob in slot %u
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 754: Deriving master key
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 773: Error deriving master key: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1017: Software attestation key missing: %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 648: Invalid key slot %u would read past end of file of size %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 109: Mode does not support padding
external/trusty/musl/src/stdlib/qsort.c
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 878: BoringSSL self-test: FAILED
trusty/user/app/keymaster/trusty_keymaster.h, Line 41: Creating TrustyKeymaster
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/openssl_err.cpp, Line 166: RSA key is too small to use with selected padding/digest
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 679: TAG_CONFIRMATION_TOKEN wrong size, was %zd expected %zd
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 105: Failed to read attestation IDs
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 226: Failed to get key type
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 858: failed (%d) to set_cookie on port %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 495: Dispatching GET_HMAC_SHARING_PARAMETERS, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 568: Dispatching KM_ATAP_READ_UUID, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 585: Dispatching KM_SET_WRAPPED_ATTESTATION_KEY, size %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 473: Malformed data found in AuthorizationSet deserialization
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 232: Closing storage session %llu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 282: Opened file %s with handle %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/attestation_record.cpp, Line 1067: Unique ID cannot be created without creation datetime
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 162: %s
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 72: No key size specified for RSA key generation
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 143: %d MGF digests specified in begin params and SHA1 not authorized
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/aes_key.cpp, Line 56: AES-GCM key must have KM_TAG_MIN_MAC_LENGTH
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/aes_key.cpp, Line 82: KM_TAG_MIN_MAC_LENGTH found for non AES-GCM key
external/trusty/musl/src/stdio/vfprintf.c
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 849: Failed (%d) to create port %s
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 276: do_dispatch #3: serialized response, %d bytes
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1265: UnwrapKey:3
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 539: Failed to open session in CreateDateForNewKey
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 495: Auth token has the challenge %llu, need %llu
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 533: Error: Device ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 200: Input too long: cannot operate on %u bytes of data with %u-byte RSA key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 87: Block mode %d not supported
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 58: Memory allocation failed
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 442: Dispatching GET_SUPPORTED_BLOCK_MODES, size: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/include/keymaster/android_keymaster_messages.h
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 242: do_dispatch #2 err: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 546: Upgrading non rollback-protected key, adding rollback protection
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 694: Deserialized blob with format: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 888: Failed to open secure storage session.
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1193: Wrapping key lacks authorization for SHA2-256
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 474: Failed to write factory reset secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 482: Failed to zero secure deletion secret entries in first block
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 504: Unable to get factory reset secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 580: Error zeroing space in extended file
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 711: Committed deletion
trusty/user/app/keymaster/openssl_keymaster_enforcement.cpp, Line 236: Failed to connect to hwkey: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/attestation_record.cpp, Line 920: Unique ID cannot be created without creation datetime
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 145: Invalid COSE_Mac0 contents
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 151: Invalid Mac0 protected: %s
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 554: Error: Serial number too large: %d
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 596: Error: Model ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 200: Imported key size (%u bits) does not match specified key size (%u bits)
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp
trusty/user/app/keymaster/trusty_aes_key.cpp, Line 256: HWWSK: export key failed (%d)
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 263: Error creating md ctx.
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 286: Signature length larger than the supported maximum signature length.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/iot/attestation/atap/libatap/atap_util.c
com.android.trusty.system-state
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 627: Cannot dispatch unknown command %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 500: Upgrading key blob
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 778: Key derivation complete
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 734: Committed deletion of secrets file.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 413: Rate-limited keys table full.  Entries will time out.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 497: Failed to construct a COSE_Encrypt ProtectedData structure
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 91: Block mode %d was specified, but not authorized by key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 75: Error reserving data in output buffer
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 256: Error parsing pkcs8 private key to EVP_PKEY.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 715: error handling message (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 376: Previous configure command failed
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 386: Provisioning command %d not allowed
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 605: Dispatching KM_GENERATE_RKP_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 610: Dispatching KM_GENERATE_CSR, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1163: UnwrapKey:0
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 485: Zeroed secrets.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 512: Secure deletion not requested.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 623: Secure deletion not requested.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 627: Need to read secure deletion secret from slot %u
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 687: Failed to open file to retrieve secure deletion data.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 704: Deleted secure key slot %u, zeroing %llu to %llu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 279: Error %d opening file %s
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 140: Failed to get key type.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 874: Initializing
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 711: configure error (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 143: failed (%d) to send_msg for chan (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 417: Dispatching EXPORT_KEY, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 804: got an empty event
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/auth_encrypted_key_blob.cpp, Line 83: Buffer management error
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 261: Error %ld opening storage session on port %s.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 171: Error %zd writing rollback record at offset %llu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 354: Failed to zero secret at offset %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 460: Bug: Auth token is the wrong size (%d expected, %d found)
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 91: %s
trusty/user/app/keymaster/secure_storage_manager.cpp
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 484: Error: Product ID already set!
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 722: Error: failed to write to file: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 62: Context initialization failed
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_key.cpp, Line 50: HMAC key must have KM_TAG_MIN_MAC_LENGTH
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/iot/attestation/atap/ops/openssl_ops.cpp
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 407: Dispatching FINISH_OPERATION, size: %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 455: Created new secure secrets file, size %llu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 468: Failed to generate %zu random bytes for factory reset secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 488: Failed to commit transaction creating secure secrets file
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 491: Committed new secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 597: Failed to commit transaction writing new deletion secret to slot %u
com.android.trusty.hwkey
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 525: Auth token has timed out
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac.cpp
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 753: Error: failed to open file '%s': %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 530: Dispatching SET_ATTESTION_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 540: Dispatching SET_ATTESTATION_CERT_CHAIN, size %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 671: key_slot == 0, nothing to delete
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 737: No secrets file existed.
com.android.trusty.keymint.kak
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 422: Failed to validate and extract the public keys for the CSR
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 286: Setting notAfter to %ld: 
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 66: Error deriving master key: %d
external/trusty/musl/src/exit/atexit.c
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1055: Failed to read attestation chain from RPMB, falling back to test chain
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/openssl_err.cpp, Line 90: Openssl error %d, %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 436: Can't open secure secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 680: Failed to open session to retrieve secure deletion data.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 725: Opened session to delete secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 137: Error attempt to read %llu bytes returned only %zd bytes
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 467: Bug: Auth token is the version %d (or is not an auth token). Expected %d
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 111: Error: existing session is stale.
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 183: Boot parameters are already set in the remote provisioning context
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 265: Input too long: %d-byte digest cannot be used with %d-byte RSA key in PSS padding mode
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 83: %d block modes specified in begin params
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 268: Expected %d-byte IV for operation, but got %d bytes
trusty/user/app/keymaster/trusty_aes_key.cpp, Line 74: HWWSK: unsupported tag (%u)
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_operation.cpp, Line 47: MAC length may not be specified for verify
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 160: Stored cert chain length is larger than the maximum cert chain length
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 189: Failed to write key and certs to slot %d (err = %d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 783: failed (%d) to set_cookie on chan %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 453: Dispatching GET_SUPPORTED_DIGESTS, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 573: Dispatching KM_SET_PRODUCT_ID, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 622: Dispatching KM_CONFIGURE_BOOT_PATCHLEVEL, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 445: Getting secure deletion data
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1203: Wrapping key must use SHA2-256
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 571: Attempting to resize file from %llu to %llu
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 585: Error: Manufacturer ID too large: %d
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 619: Error: [%d] decoding from file '%s'
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 148: MGF Digest %d not supported
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 129: %d digests specified in begin params and NONE not authorized
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/symmetric_key.cpp, Line 91: Expected %d-bit key data but got %d-bit key
trusty/user/app/keymaster/trusty_aes_key.cpp, Line 114: HWWSK: generate key blob failed(%d)
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 155: Failed to read som cert chain from slot %d (err = %d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 769: failed (%d) to accept on port %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 639: access denied for client uuid
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 699: invalid message of size (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 520: Dispatching DELETE_ALL_KEYS, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 563: Dispatching KM_ATAP_SET_CA_RESPONSE_FINISH, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1211: UnwrapKey:2
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 441: Opened non-empty secure secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 577: Resized file to %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 413: Couldn't get a pointer to the remote provisioning context, returned null.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 171: Test key in production request
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 523: Error: Brand ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 163: Got certificate date params:  NotBefore = %ld, NotAfter = %ld
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ec_key_factory.cpp, Line 107: Unable to get EC group for curve %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 465: Dispatching GET_SUPPORTED_EXPORT_FORMATS, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 515: Dispatching DELETE_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 545: Dispatching KM_ATAP_GET_CA_REQUEST, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 551: Dispatching KM_ATAP_SET_CA_RESPONSE_BEGIN, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 456: Got secure deletion data, FR size = %zu, SD size = %zu, slot = %u
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1171: UnwrapKey:1
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 462: Malformed data found in AuthorizationSet deserialization
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/ocb_utils.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 398: Auth required but no matching auth token found
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 425: Usage count-limited keys table full, until reboot.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 460: Failed to construct ProtectedData: %s
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/include/keymaster/cppcose/cppcose.h
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 761: Error: encoding fields to file '%s'
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ec_key_factory.cpp, Line 71: Curve key size %d and specified key size %d don't match
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_key.cpp, Line 68: %d digests specified for HMAC key
trusty_keymaster
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 719: Sending %d-byte response
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 604: Software key blobs are not supported.
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 643: Deserialized blob with format: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1197: Wrapping key lacks authorization for padding OAEP
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 482: Malformed data found in AuthorizationSet deserialization
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 449: Read factory-reset secret, size %zu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 133: Error %zd reading file
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/include/keymaster/remote_provisioning_utils.h
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 111: Unrecognized root of EEK chain
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 791: Error: failed to open file '%s': %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ec_key_factory.cpp, Line 55: %s
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 693: failed to read msg (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 380: Bootloader command %d not allowed after configure command
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/ocb_utils.cpp, Line 171: Failed to validate authentication tag during key decryption
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 174: Wrote %zd of %zu bytes
trusty/user/app/keymaster/openssl_keymaster_enforcement.cpp, Line 253: KAK has the wrong size: %zu != %zu.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 516: Key requires match of auth type mask 0%uo, but token contained 0%uo
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 737: Error: failed to read from file: %d
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 772: Error: failed to commit write transaction for file '%s': %d
external/trusty/musl/src/time/__secs_to_tm.c
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 832: Failed (%d) to create port %s
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 448: Dispatching GET_SUPPORTED_PADDING_MODES, size: %d
trusty/kernel/lib/ubsan/ubsan.c
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/attestation_record.cpp
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 564: Error: IMEI ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 442: Input too long: cannot verify %u-byte message with PKCS1 padding && %u-bit key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 203: Error encrypting final block: %s
com.android.trusty.hwwsk
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 840: failed (%d) to set_cookie on port %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 776: failed to allocate context on chan %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 470: Dispatching GET_KEY_CHARACTERISTICS, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 490: Dispatching CONFIGURE, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 764: Could not allocate memory for master key buffer
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1275: UnwrapKey:4
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 722: Failed to open session to delete secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 729: Deleted secrets file
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 740: Failed to delete secrets file
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 325: Error (%d) committing transaction
trusty/user/app/keymaster/openssl_keymaster_enforcement.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 501: Auth token SIDs %llu and %llu do not match key SID %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 152: Using TAG_CERTIFICATE_NOT_BEFORE: %lu
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 899: wait_any failed (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 743: failed (%d) to handle event on channel %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 97: failed to wait for outgoing queue to free up
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 428: Malformed data found in AuthorizationSet deserialization
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 441: Malformed data found in AuthorizationSet deserialization
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/key_blob_utils/auth_encrypted_key_blob.cpp, Line 276: Invalid key blob format %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 445: Failed to read factory reset secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 591: Failed to write new deletion secret to key slot %u
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 640: Failed to open file to get secure deletion data.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 163: Attempt to write past EOF
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 441: Failed to generate COSE_Mac0 over the public keys to sign.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 102: Padding mode %d was specified, but not authorized by key
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 242: Failed to read som cert chain from slot %d (err = %d)
trusty/user/app/keymaster/atap/trusty_atap_ops.cpp, Line 251: Error parsing pkcs8 format private key.
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 200: Cert chain could not be deleted.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 392: Dispatching GENERATE_KEY, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 402: Dispatching UPDATE_OPERATION, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 616: Dispatching KM_CONFIGURE_VENDOR_PATCHLEVEL, size %d
com.android.trusty.storage.client.tp
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 431: Trying to open secure secrets file
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 344: zero_entries called with invalid offset %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 408: Rate-limited keys table not allocated.  Rate-limited keys disabled
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 136: Invalid COSE_Mac0 structure
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 177: %s
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 804: Error: decoding fields from file '%s'
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp, Line 54: Couldn't open hwkey session: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 357: Input too long: cannot sign %u-byte message with PKCS1 padding with %u-bit key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 141: Digest %d was specified, but not authorized by key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/symmetric_key.cpp, Line 56: Error generating %d bit symmetric key
trusty/user/app/keymaster/trusty_aes_key.cpp, Line 36: HWWSK: connect failed (%d)
trusty/user/app/keymaster/trusty_aes_key.cpp, Line 80: HWWSK: missing key size tag
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 371: Command %d not allowed before configure command
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 397: Dispatching BEGIN_OPERATION, size: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1006: Failed to open secure storage session.
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1186: Wrapping key did not have KM_PURPOSE_WRAP
com.android.trusty.hwrng
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 424: Trying to open a session to read factory reset secret
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 732: Failed to commit deletion of secrets file.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 256: Opening storage session on port %s (wait: %s)
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 376: Failed to read block of secrets
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/keymaster_enforcement.cpp, Line 454: Authentication required, but auth token not provided
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 119: Failed to get EEK: %s
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 182: MAC tag mismatch
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 94: Padding mode %d not supported
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 195: Failed to read cert chain length.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 278: Error serializing response: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 608: Invalid keystore blob prefix value %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1207: Wrapping key must use OAEP padding
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 661: Read secure deletion secret, size: %zu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 265: Opened storage session %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/openssl_utils.cpp, Line 93: EVP key algorithm was %d, not the expected %d
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 543: Error: Product ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/operation.cpp, Line 91: %d padding modes specified in begin params
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 71: Error deriving key
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 47: HAL sent invalid message version %d, crashing
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 187: Failed to delete cert chain.
trusty/user/app/keymaster/trusty_keymaster.cpp, Line 242: Failed to read cert chain length, initialize to 0.
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 674: failed (%d) to get_msg for chan (%d), closing connection
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 500: Dispatching COMPUTE_SHARED_HMAC, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 579: Dispatching KM_CLEAR_ATTESTATION_CERT_CHAIN, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 595: Dispatching KM_EARLY_BOOT_ENDED, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 208: do_dispatch #1 err: %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1014: Failed to read attestation key from RPMB, falling back to test key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/authorization_set.cpp, Line 498: Malformed data found in AuthorizationSet deserialization
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 550: Opened file to store secure deletion secret.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 696: Attempted to delete invalid key slot %u
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 287: Error %d reading size of file %s
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 104: Closing file handle %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 97: Key is missing required label 'CURVE'
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 574: Error: MEID ID too large: %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 143: Using TAG_ORIGINATION_EXPIRE_DATETIME: %lu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 158: Using TAG_CERTIFICATE_NOT_AFTER: %lu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 76: Invalid key size of %u bits specified for RSA key generation
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 262: No IV provided
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 66: Error setting peer key
com.android.trusty.hwkeybox
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 1047: Failed to open secure storage session.
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/openssl_err.cpp, Line 49: %s
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 460: Resized secure secrets file to size %llu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 587: Writing new deletion secret to key slot %u
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 681: Error: [%d] decoding from file '%s'
trusty/user/app/keymaster/trusty_remote_provisioning_context.cpp
com.android.trusty.hwbcc
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/ecdh_operation.cpp, Line 51: Error decoding key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_operation.cpp, Line 52: MAC length must be a multiple of 8
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 734: error event (0x%x) for chan (%d)
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 432: Dispatching ADD_RNG_ENTROPY, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 437: Dispatching GET_SUPPORTED_ALGORITHMS, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 485: Dispatching UPGRADE_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 249: do_dispatch #2: serialized response, %d bytes
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 818: no handler for event (0x%x) with handle %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 574: Failed (%d) to grow file to make room for a key slot
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 656: Failed to read secret from slot %u
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 188: Attempt to resize invalid file handle
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 157: Attempt to write to invalid file handle
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster.cpp, Line 180: GetVersion2 results: %d, %d, %d, %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 156: Unsupported Mac0 algorithm
trusty/user/app/keymaster/secure_storage_manager.cpp, Line 796: Error: failed to get size of attributes file '%s': %d
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 62: No public exponent specified for RSA key generation
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 60: AES GCM key must have KM_TAG_MIN_MAC_LENGTH
com.android.trusty.keymaster.secure
com.android.trusty.keymaster
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 459: Dispatching GET_SUPPORTED_IMPORT_FORMATS, size: %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 480: Dispatching ATTEST_KEY, size %d
trusty/user/app/keymaster/ipc/keymaster_ipc.cpp, Line 505: Dispatching VERIFY_AUTHORIZATION, size %d
trusty/user/app/keymaster/trusty_keymaster_context.cpp, Line 973: Failed to derive unique ID HBK: %d
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 493: Got factory reset secret of size %zu
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 554: Error while searching for key slot
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 600: Committed new secret.
trusty/user/app/keymaster/trusty_secure_deletion_secret_storage.cpp, Line 195: Error %d resizing file from %llu to %llu
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/android_keymaster_messages.cpp
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/android_keymaster/remote_provisioning_utils.cpp, Line 168: Production key in test request
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/certificate_utils.cpp, Line 139: Using TAG_ACTIVE_DATETIME: %lu
trusty/user/app/keymaster/trusty_keymaster_enforcement.cpp, Line 82: Error getting time. Error: %d, time: %lld
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_key_factory.cpp, Line 191: Imported public exponent (%u) does not match specified public exponent (%u)
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/rsa_operation.cpp, Line 151: MGF Digest %d was specified, but not authorized by key
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/block_cipher_operation.cpp, Line 274: Expected %d-byte nonce for GCM operation, but got %d bytes
/usr/local/google/buildbot/src/googleplex-polygon-android/trusty-whitechapel-sc-v2-release/system/keymaster/km_openssl/hmac_operation.cpp, Line 39: HMAC key must have KM_TAG_MIN_MAC_LENGTH
trusty/user/app/storage/block_tree.h
trusty/user/app/storage/block_mac.h
trusty/user/app/storage/block_tree.c
trusty/user/app/storage/transaction.c
com.android.trusty.storage.client.td
com.android.trusty.storage.proxy
trusty/user/app/storage/rpmb.c
trusty/user/app/storage/client_tipc.c
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.system-state
trusty/user/app/storage/super.c
com.android.trusty.hwkey
trusty/user/app/storage/block_allocator.c
trusty/kernel/include/shared/lk/reflist.h
trusty/user/app/storage/proxy.c
trusty/user/app/storage/block_set.c
trusty/user/app/storage/ipc.c
trusty/user/app/storage/file.c
trusty/user/app/storage/crypt.c
trusty/user/app/storage/block_map.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/app/storage/block_range.h
com.android.trusty.storage.client.tp
com.android.trusty.hwrng
trusty/user/app/storage/block_mac.c
trusty/user/app/storage/block_device_tipc.c
trusty/user/app/storage/block_cache.c
com.android.trusty.storage.client.tdea
com.android.trusty.storage.client.tdp
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_object_table.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto.c
trusty/vendor/widevine/cdm/oemcrypto/odk/src/odk_serialize.c
trusty/vendor/widevine/cdm/oemcrypto/opk/serialization/common/opk_serialization_base.c
com.android.trusty.storage.client.td
trusty/user/app/widevine/secure_buffer.c
external/trusty/musl/src/stdlib/qsort.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_usage_table.c
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.kernel.handle_prot
....TrustyWidevineDerivationData
trusty/vendor/widevine/cdm/oemcrypto/opk/serialization/common/shared_buffer_allocator.c
trusty/user/app/widevine/interface_impls/initialize_terminate_interface.c
trusty/user/app/widevine/interface_impls/root_of_trust_layer2.c
com.android.trusty.system-state
trusty/user/app/widevine/interface_impls/device_key_interface.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_session.c
com.android.trusty.hwkey
com.android.trusty.widevine
trusty/vendor/widevine/cdm/oemcrypto/odk/src/serialization_base.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_test_impl/cmac_util.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_output.c
trusty/vendor/widevine/cdm/oemcrypto/opk/serialization/common/bump_allocator.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_reference/clock_and_gn_layer1.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_key_table.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_reference/config_interface_wrap_asymmetric.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_test_impl/logging_interface.c
trusty/user/app/widevine/interface_impls/crypto_interface.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_test_impl/rsa_util.c
trusty/user/app/widevine/interface_impls/persistent_storage_layer2.c
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_session_table.c
trusty/user/base/lib/tipc/tipc.c
trusty/vendor/widevine/cdm/oemcrypto/odk/src/odk_message.c
com.android.trusty.hwrng
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/wtpi_reference/root_of_trust_layer1.c
com.android.trusty.hwkeybox
trusty/vendor/widevine/cdm/oemcrypto/opk/oemcrypto_ta/oemcrypto_session_key_table.c
com.android.trusty.storage.client.tdp
trusty/kernel/lib/app_manifest/app_manifest.c
trusty/user/base/app/apploader/cose.cpp
trusty/user/base/lib/hwaes/hwaes.c
trusty/user/base/app/apploader/apploader.c
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.system-state
com.android.trusty.hwaes
com.android.trusty.apploader.secure
trusty/user/base/lib/tipc/tipc_srv.c
com.android.trusty.hwkey
external/trusty/musl/src/exit/atexit.c
trusty/user/base/app/apploader/app_version.cpp
com.android.trusty.apploader
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
com.android.trusty.storage.client.tp
com.android.trusty.hwrng
trusty/user/base/app/apploader/apploader_package.cpp
com.android.trusty.apploader.
iTrustyApp
iTrustyApp
external/trusty/musl/src/stdio/vfprintf.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/base/app/metrics/metrics.c
com.android.trusty.metrics
com.android.trusty.metrics.consumer
trusty/user/whitechapel/gsa/lib/gscproxy/srv/gscproxy-srv.c
trusty/user/whitechapel/tz/app/gsaproxy/hwmgr-srv.c
com.android.trusty.sensor_mute_proxy
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.gsa.hwmgr.tpu
com.android.trusty.kernel.smc
com.android.trusty.gsa.hwmgr.aoc
trusty/user/base/lib/tipc/tipc_srv.c
com.android.trusty.hwwsk
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
trusty/hardware/google/whitechapel/gsa/dev/mbox/user/mbox-user.c
com.android.trusty.gsa.hwmgr.tpu.wakelock
'struct (anonymous struct at trusty/user/whitechapel/tz/app/gsaproxy/hwmgr-srv.c:578:21) [8]'
trusty/user/base/lib/hwbcc/srv/srv.c
com.android.trusty.kernel.cdt
external/trusty/musl/src/stdio/vfprintf.c
trusty/user/whitechapel/tz/app/hwbcc/hwbcc_iecs.c
trusty/user/base/lib/tipc/tipc_srv.c
com.android.trusty.hwkey
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/hwbcc/common/swbcc.c
trusty/user/base/lib/tipc/tipc.c
com.android.trusty.hwrng
com.android.trusty.hwiecs
com.android.trusty.hwbcc
com.android.trusty.faceauth.encrypt.key.0
trusty/user/whitechapel/tz/app/hwcrypto/iecs/srv.c
trusty/user/whitechapel/tz/app/hwcrypto/keybox/srv.c
trusty/user/base/lib/libc-trusty/time.c
trusty/user/whitechapel/tz/app/hwcrypto/sss/sss.c
com.android.trusty.apploader.sign.key.1
trusty/user/whitechapel/tz/app/hwcrypto/hwrng_srv.c
trusty/user/whitechapel/gsa/lib/gscproxy/client/client.c
com.android.trusty.apploader.sign.key.0
com.android.trusty.kernel.cdt
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.system-state
com.android.trusty.kernel.smc
trusty_nanosleep
com.android.trusty.hwaes
com.android.trusty.apploader.encrypt.key.1
trusty/user/whitechapel/tz/app/hwcrypto/hwkey_dev.c
com.android.trusty.hwkey
com.android.trusty.keymint.kak
external/trusty/musl/src/exit/atexit.c
trusty/user/whitechapel/tz/app/hwcrypto/hwkey_srv.c
trusty/user/whitechapel/tz/app/hwcrypto/hwaes/srv.c
com.android.trusty.apploader.encrypt.key.0
com.android.trusty.kernel.ldfw
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/whitechapel/tz/base/lib/gsc/generated/nugget/app/keymaster/keymaster.pb.cc
trusty/user/whitechapel/tz/base/lib/gsc/generated/nugget/app/avb/avb.pb.cc
com.android.trusty.hwrng
com.android.trusty.hwiecs
trusty/user/whitechapel/tz/app/hwcrypto/iecs/iecs.c
com.android.trusty.hwkeybox
com.android.trusty.spi.fingerprint
trusty/user/base/lib/libc-trusty/time.c
external/trusty/musl/src/stdio/vfprintf.c
trusty_nanosleep
trusty/user/base/lib/tipc/tipc_srv.c
trusty/user/base/lib/spi/common/utils.c
trusty/hardware/google/whitechapel/common/dev/usi/user/spi/spi-user.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/base/lib/spi/srv/batch/batch.c
com.android.trusty.kernel.fp_spi_dma.spdma
trusty/user/base/lib/spi/srv/tipc/tipc.c
trusty/user/whitechapel/tz/app/fp-spi/fingerprint_spi_server/usi_spi-srv.c
com.android.trusty.kernel.fp_spi_dma.spdma
com.android.trusty.secure_camera
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.kernel.smc
trusty/user/base/lib/tipc/tipc_srv.c
trusty/user/whitechapel/tz/app/secure_camera/secure_camera.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
com.android.trusty.sensor_mute
com.android.trusty.sensor_mute_proxy
external/trusty/musl/src/stdio/vfprintf.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/user/whitechapel/tz/app/sensor_mute/sensor_mute_helper.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
com.android.trusty.storage.client.tp
external/trusty/musl/src/stdio/vfprintf.c
%s: %d: trusty=%d/%d prov=%d/%d app=%d roll=%d/%d
com.android.trusty.system-state
trusty/user/base/lib/tipc/tipc_srv.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/whitechapel/tz/app/system_state_server/main.c
trusty/user/base/lib/tipc/tipc.c
trusty/user/base/lib/libc-trusty/time.c
trusty/vendor/lassen/dpu/tz/app/secure_fb/gs101/decon_reg.c
trusty/user/base/lib/secure_fb/srv/secure_fb_server.c
com.android.trusty.kernel.cdt
trusty/vendor/lassen/dpu/tz/app/secure_fb/gs101/dpp_reg.c
external/trusty/musl/src/stdio/vfprintf.c
com.android.trusty.secure_fb
com.android.trusty.kernel.handle_prot
com.android.trusty.kernel.smc
trusty_nanosleep
trusty/user/base/lib/secure_dpu/secure_dpu.c
trusty/user/base/lib/tipc/tipc_srv.c
trusty/vendor/lassen/dpu/tz/app/secure_fb/gs101/dsim_reg.c
trusty/kernel/lib/ubsan/ubsan.c
trusty/user/base/lib/tipc/tipc.c
trusty/vendor/lassen/dpu/tz/app/secure_fb/secure_dpu_drv.c
com.android.trusty.secure_dpu
arbung@MacBook-Air-romanticunchanging extracted % 
```

## tzfw:
```
void UndefinedFunction_0005ffe2(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined2 uVar3;
  undefined *puVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int unaff_r7;
  undefined4 in_cr0;
  undefined4 in_cr2;
  undefined4 in_cr3;
  undefined4 in_cr4;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr7;
  undefined4 in_cr10;
  undefined4 in_cr15;
  undefined8 unaff_d10;
  undefined8 unaff_d9;
  undefined8 in_d7;
  
  *(int *)(*(int *)(unaff_r7 + 0x70) + 0x94) = unaff_r7 + -0x33;
  uVar5 = ram0x0000001e;
  bVar2 = *(byte *)(DAT_00060100 + -0x25);
  iVar7 = DAT_00060168 + -0x3a;
  *(uint *)(bVar2 + 0x20) = (uint)*DAT_00060160 + (param_3 + 0x16) * -0x1000000;
  ram0x0000001e = uVar5;
  puVar4 = SysTick;
  uVar5 = ram0x0000001e;
  iVar6 = (uint)bVar2 * 0x40;
  coprocessor_moveto(3,5,1,iVar7,in_cr15,in_cr3);
  VectorRoundShiftRight(in_d7,0x10);
  cRamffffffd0 = (char)*(undefined4 *)(iVar6 + -0xd) + '\\';
  uRamfffffffc = 0xffffffcc;
  Reset = (undefined *)(iVar6 + -0x1f);
  NMI = (undefined *)0x0;
  DAT_000004cc = 0x480;
  VectorRoundShiftRight(in_d7,0x10);
  DAT_50000004 = 0;
  DAT_000000fb = 0;
  DAT_00000103 = 0x3b;
  DAT_00000107 = 0;
  DAT_0000010b = 0;
  _MasterStackPointer = 0x160000;
  DAT_4fffffbd = 0xbd;
  VectorPairwiseAddLong(unaff_d10,1);
  iVar6 = (int)((uint)(int)*(short *)(ram0x00000016 + 0x2b) >> 0x14) >> 8;
  iVar7 = iVar6 + 0x16;
  iVar8 = (int)SysTick * 0x1000000;
  DAT_000000ff = (uint)CONCAT21((short)iVar7,0x16);
  *(int *)(iVar6 + 0x86) = iVar8;
  ram0x0000001e = uVar5;
  uVar5 = ram0x0000001e;
  *(undefined4 *)(puVar4 + 0x36) = 200;
  ram0x0000001e = uVar5;
  uVar5 = ram0x0000001e;
  iRamfffffe50 = (int)(char)puVar4[iVar7 >> (iVar8 + 0x4cU & 0xff)];
  iRamfffffd94 = iRamfffffe50 + -0x48;
  coprocessor_function2(1,0xb,2,in_cr0,in_cr2,in_cr7);
  UsageFault._0_2_ = (ushort)UsageFault._1_1_;
  coprocessor_function2(7,2,4,in_cr6,in_cr10,in_cr15);
  VectorRoundShiftRight(unaff_d9,0x10);
  DAT_00000047 = (int)CONCAT21(Reserved2._0_2_,Reserved2._2_1_) >> 8;
  coprocessor_function(0xe,6,0,in_cr4,in_cr5,in_cr15);
                    /* WARNING: Does not return */
  pcVar1 = (code *)software_udf(0x1b,0x5fece);
  uVar3 = Reserved2._0_2_;
  unique0x10000066 = uVar5;
  uVar5 = unique0x10000066;
  Reserved2._0_2_ = uVar3;
  (*pcVar1)();
  uVar3 = Reserved2._0_2_;
  ram0x0000001e = ram0x0000001e;
  Reserved2._0_2_ = uVar3;
}

```

![[Снимок экрана 2025-01-26 в 17.07.43.png]]


