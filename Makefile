all:
	gcc core/*.c core/packet/*.c core/pipeline/*.c core/modules/**/*.c -Icore -Icore/packet -o ngfw-simulator
