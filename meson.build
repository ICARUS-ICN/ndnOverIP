project('ndnOverIP', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14'])

ndn = [dependency('libndn-cxx'), dependency('libpcap')]

executable('ndnOverIP',
           ['gateway.cpp',
           'Producer.cpp',
           'util.cpp',
           'cola_paquetes.cpp',
           'main.cpp'],
           dependencies: ndn,
           install : true)
