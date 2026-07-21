build_lib_example(
  NAME rpl-6lowpan-simple
  SOURCE_FILES rpl-6lowpan-simple.cc
  LIBRARIES_TO_LINK
    ${libapplications}
    ${libcore}
    ${libinternet}
    ${liblr-wpan}
    ${libmobility}
    ${libnetwork}
    ${librpl}
    ${libsixlowpan}
)
