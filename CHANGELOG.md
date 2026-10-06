# Changelog

## [0.9.10](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.9...v0.9.10) (2026-10-06)


### Bug Fixes

* keep the Windows channel answering when the host is slow to drain ([ef4c8be](https://github.com/weaveplatform/weaveplatform-agent-core/commit/ef4c8bec11a2cd304ebbf8fc7bbdfaa6f138fc25))
* open the Windows channel device for overlapped I/O ([7cc1802](https://github.com/weaveplatform/weaveplatform-agent-core/commit/7cc1802be6ece4c35687bb78066d4c6451118625))
* report a module that exits after its handshake line ([4b05826](https://github.com/weaveplatform/weaveplatform-agent-core/commit/4b058267f803eb0fbbfe85e8f9345151e12cb746))
* Windows guest channel I/O and console-session modules ([188531f](https://github.com/weaveplatform/weaveplatform-agent-core/commit/188531f9865ce0b8b50559f4eeb9ecbc7ecc706d))

## [0.9.9](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.8...v0.9.9) (2026-10-05)


### Features

* sign core's Windows binaries and scripts with Authenticode ([233031e](https://github.com/weaveplatform/weaveplatform-agent-core/commit/233031e8ca6ffa16c67a72817e024f69340fb087))
* trust the module code-signing certificate when installing on Windows ([7bad8a4](https://github.com/weaveplatform/weaveplatform-agent-core/commit/7bad8a462ad3f935d2c942c8fe0fd96b2c673d6a))
* watch the modules directory on Windows ([809de6e](https://github.com/weaveplatform/weaveplatform-agent-core/commit/809de6eba4115fa574c99d69424fed075bf9c1cc))
* Windows guests: signed install, module trust and hot reload ([b4f37c4](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b4f37c46b4b3a1b62820e381a0a4edcdb5762793))


### Bug Fixes

* accept an Authenticode thumbprint pin without a subject ([c586b5c](https://github.com/weaveplatform/weaveplatform-agent-core/commit/c586b5c42fadf79c0c52d98f0ee9382361ff494f))
* drop the Windows signing credentials checklist ([8d01bc3](https://github.com/weaveplatform/weaveplatform-agent-core/commit/8d01bc37c423d73fc1c006958dfd9c0dad44dc2c))
* fail rather than skip the elevated Windows tests in CI ([50b4a11](https://github.com/weaveplatform/weaveplatform-agent-core/commit/50b4a11a040392230d731efcad68b98694f3c378))
* Windows store, watch and install-script faults found on the runner ([1219572](https://github.com/weaveplatform/weaveplatform-agent-core/commit/121957205c21a94a4381d85f315e509dd2f46e0d))

## [0.9.8](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.7...v0.9.8) (2026-10-05)


### Bug Fixes

* keep the macOS host channel draining and recover a broken stream ([dea4ad3](https://github.com/weaveplatform/weaveplatform-agent-core/commit/dea4ad3021c9b056a6046ef4d57c1a2b389c44a5))
* macOS session modules, host channel stalls and weavectl's default socket ([542c404](https://github.com/weaveplatform/weaveplatform-agent-core/commit/542c404aa2285157141e2ace796ddd37f9be5c38))
* point weavectl at the control socket weaveboot's core binds ([b96052a](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b96052af4241757b3c3c7b856ea4052dd3fd034c))
* run macOS session modules without chroot ([f4d64f9](https://github.com/weaveplatform/weaveplatform-agent-core/commit/f4d64f9cec7a8617752e46328e93d62278b37aff))

## [0.9.7](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.6...v0.9.7) (2026-10-05)


### Bug Fixes

* **packaging:** retry stapling when Apple's ticket service times out ([a5ef846](https://github.com/weaveplatform/weaveplatform-agent-core/commit/a5ef8462f51b9b34f0e9a5e4d9a00338571b24a2))
* **packaging:** retry stapling when Apple's ticket service times out ([b9b5734](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b9b5734b3170f53a054e642e021fc8da8ae361bb))

## [0.9.6](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.5...v0.9.6) (2026-10-05)


### Features

* **packaging:** sign and notarise the macOS package and binaries ([2707ea7](https://github.com/weaveplatform/weaveplatform-agent-core/commit/2707ea781000210f9231be9414658658861adaed))
* **packaging:** sign and notarise the macOS package and binaries ([063b6bc](https://github.com/weaveplatform/weaveplatform-agent-core/commit/063b6bcf3e4293554a4f260f5d63c57cd0571c26))


### Bug Fixes

* **packaging:** keep the keychain password apart from the p12 password ([67fd01f](https://github.com/weaveplatform/weaveplatform-agent-core/commit/67fd01f3230066b711ea50d0e95cace60014fdfa))
* **verify:** mark the codesign display call for gosec's taint check ([0adb0fb](https://github.com/weaveplatform/weaveplatform-agent-core/commit/0adb0fbd5be4441228f559b3d4838389a67db943))

## [0.9.5](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.4...v0.9.5) (2026-10-04)


### Bug Fixes

* **verify:** pass the macOS code requirement to codesign inline ([b48a737](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b48a7375865da6fd3b355de66653e76d92294433))
* **verify:** pass the macOS code requirement to codesign inline ([0b20517](https://github.com/weaveplatform/weaveplatform-agent-core/commit/0b205179ad3e106c632b1e819aa10c141ebcd485))

## [0.9.4](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.3...v0.9.4) (2026-10-04)


### Features

* install the channel trust anchor from boot media ([3533ce3](https://github.com/weaveplatform/weaveplatform-agent-core/commit/3533ce3cd8c4beb6ba67a309d35d1ce47174e96d))
* **packaging:** macOS package and launchd daemon ([9531560](https://github.com/weaveplatform/weaveplatform-agent-core/commit/9531560e58592466b47cae812ec08e460bcafa6d))
* run weave-agent in macOS guests ([94b40c2](https://github.com/weaveplatform/weaveplatform-agent-core/commit/94b40c2d7e74c151657f4323c3814ba434e1519c))
* watch the modules directory on macOS ([5431935](https://github.com/weaveplatform/weaveplatform-agent-core/commit/543193503ce72c2f68a90c8efb6e6b4941753c09))

## [0.9.3](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.2...v0.9.3) (2026-10-04)


### Features

* **packaging:** reload weave-agent through systemd ([b795897](https://github.com/weaveplatform/weaveplatform-agent-core/commit/b795897d97ed18b4ad0b4e0c52412eef5469df26))
* reload modules without restarting core ([bda42f6](https://github.com/weaveplatform/weaveplatform-agent-core/commit/bda42f6521453ef3acfb2f7fe2f837cc5d91043b))
* reload modules without restarting core ([3e06d7d](https://github.com/weaveplatform/weaveplatform-agent-core/commit/3e06d7dee466333062ec14d19ed73a824c25ae41))


### Bug Fixes

* stage module binaries on Windows so a running module never locks its install ([7265bf8](https://github.com/weaveplatform/weaveplatform-agent-core/commit/7265bf845835d13e156d151aae1d8cd542cc72d4))

## [0.9.2](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.1...v0.9.2) (2026-10-04)


### Features

* module registry for core, hosts and modules ([c9f4fff](https://github.com/weaveplatform/weaveplatform-agent-core/commit/c9f4fff9c711c187e1428b2e7868ad3185449d17))
* module registry for core, hosts and modules ([53c0778](https://github.com/weaveplatform/weaveplatform-agent-core/commit/53c0778ff7090a5c43b3df62aae9efff30ae8050))

## [0.9.1](https://github.com/weaveplatform/weaveplatform-agent-core/compare/v0.9.0...v0.9.1) (2026-10-04)


### Bug Fixes

* **packaging:** create the weave-agent service account ([6893bda](https://github.com/weaveplatform/weaveplatform-agent-core/commit/6893bdabef36825a416204339d59d42fdfc8e238))
* service modules start on a stock Linux install ([455a5f5](https://github.com/weaveplatform/weaveplatform-agent-core/commit/455a5f546cdf1dd430300f9288b1d6e54cdd042c))
* stage module binaries where a service module can run them ([706aaa8](https://github.com/weaveplatform/weaveplatform-agent-core/commit/706aaa8ff761c8578d12a365cdf627cce3e2f59d))

## [0.9.0](https://github.com/weaveplatform/weaveplatform-agent-core-next/compare/v0.8.1...v0.9.0) (2026-10-03)


### Features

* weave agent core ([07fede0](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/07fede0f35d8c50e456e95d35378d02894902659))
* weave agent core ([453e7a2](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/453e7a2e944e1470704c4fd3ee1a1bbf888c51a9))


### Bug Fixes

* LF checkouts on Windows and gRPC 1.83.2 in the protocol-1 fixture ([4e6bf49](https://github.com/weaveplatform/weaveplatform-agent-core-next/commit/4e6bf496ed1448ecc44b4cf3591cb6ef5d3224e1))
