TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt


SOURCES += main.c \
    layer_application.c \
    layer_security.c \
    layer_trans.c \
    pkcs/p11_generalpurpose.c \
    pkcs/p11_slot_token_management.c \
    pkcs/p11_store.c \
    pkcs/p11_session_management.c \
    pkcs/p11_object_function.c \
    pkcs/p11_crypto_function.c \
    pkcs/pkcs_apdu.c \
    pkcs/pkcs.c

HEADERS += \
    layer_application.h \
    layer_security.h \
    layer_trans.h \
    pkcs/pkcs_define.h \
    pkcs/pkcs.h \
    pkcs/p11_generalpurpose.h \
    pkcs/p11_slot_token_management.h \
    pkcs/p11_store.h \
    pkcs/p11_session_management.h \
    pkcs/p11_object_function.h \
    pkcs/p11_crypto_function.h \
    pkcs/pkcs_apdu.h

