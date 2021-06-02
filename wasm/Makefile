

main:
	emcc -Os -Wall ../main.c ../fileLib.c ../network.c ../vmrp.c ../utils.c ../debug.c ../rbtree.c ../bridge.c ../memory.c  \
		../elfload.c ../elfloader.c \
		./unicorn/libunicorn.a \
		-s EXPORTED_FUNCTIONS="['_main', '_malloc', '_free']" \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s ALLOW_TABLE_GROWTH \
		-s USE_SDL=2 \
		-s USE_ZLIB=1 \
		-s WASM=1 \
		-s FORCE_FILESYSTEM=1 \
		-o dist/vmrp.js

		#--preload-file ./fs@/

		