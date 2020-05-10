LD_FLAGS = -L./lib -Wl,-rpath,./lib
CC_FLAGS = -Wall --pedantic-errors -g -I./libgcrypt/src

all : 
	g++ $(LD_FLAGS) $(CC_FLAGS) encryptoracle.c -o encrypt -lgcrypt
	g++ $(LD_FLAGS) $(CC_FLAGS) decryptoracle.c -o decrypt -lgcrypt
debug :
	g++ $(LD_FLAGS) $(CC_FLAGS) -DEBUG encryptoracle.c -o encrypt -lgcrypt
	g++ $(LD_FLAGS) $(CC_FLAGS) -DEBUG decryptoracle.c -o decrypt -lgcrypt
clean : 
	rm -rf encrypt decrypt *~
