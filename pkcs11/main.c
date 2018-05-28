#include "layer_application.h"
#include "pkcs/pkcs.h"


int main() {
	application_handle app;
	application_init(&app);



	application_final(&app);
	return 0;
}
