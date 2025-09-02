Author's solution for Translator

The idea is to overflow file descriptors, leading to the result in which program seeks the random from user-controlled stdin rather than /dev/urandom
