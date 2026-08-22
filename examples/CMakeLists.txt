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

build_lib_example(
  NAME rpl-paper-evaluation
  SOURCE_FILES rpl-paper-evaluation.cc
  LIBRARIES_TO_LINK
    ${libapplications}
    ${libcore}
    ${libflow-monitor}
    ${libinternet}
    ${libmobility}
    ${libnetwork}
    ${librpl}
)
