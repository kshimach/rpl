build_lib_example(
  NAME rpl-6lowpan-simple
  SOURCE_FILES rpl-6lowpan-simple.cc
  LIBRARIES_TO_LINK
    ${libcore}
    ${libinternet}
    ${libinternet-apps}
    ${liblr-wpan}
    ${libmobility}
    ${libnetwork}
    ${librpl}
    ${libsixlowpan}
)
