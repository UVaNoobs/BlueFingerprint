/**
   El proyecto BlueFingerprint consiste en el establecimiento una conexion segura entre un movil y una placa controladora por medio
   de Bluetooth de manera que la placa controladora sea capaz de abrir un cerrojo unicamente bajo la autenticacion
   de la identidad de un usuario legitimo. El objetivo final es crear un sustitutivo de las llaves fisicas para cerraduras
   reales que verifique de manera mas segura la identidad del usuario que pretende abrirla.

   Dado que todo cerrojo fisico tiene, al menos, un usuario legitimo; todos los usuarios del sistema estan supeditados
   a la autorizacion de un usuario master del cual se obtienen las credenciales en la primera conexion de la historia
   de la placa.

   Dado que una placa representa una cerradura, todas las cerraduras presentan la posibilidad de tener multiples usuarios
   capaces de abrirlas, por lo que admiten varios usuarios validos. Del mismo modo, en el mundo fisico un usuario no solo
   tiene la llave de un cerrojo, sino que puede poseer la llave de varios, por lo que un mismo usuario podra establecer
   tambien sesiones de conexion independientes con varias placas controladoras que implementen el sistema sin que esto presente
   una vulnerabilidad en la conexion.

   Para lograr el objetivo, la verificacion de identidad se divide en tres partes:
   -Verificacion biometrica por parte del movil que impide establecer la conexion en caso de suplantacion, realizada
   gracias al analisis de huella dactilar integrado en el SO Android.
   -Integridad de las peticiones de conexion mediante un codigo de validacion aleatorio y una clave simetrica unica
   para cada dispositivo capaz de establecer una conexion con la placa. Se implementa el cifrado AES mediante una
   libreria publica.
   -Proteccion de las modificaciones en los registros de usuarios permitidos mediante un sistema de contraseña y
   un unico usuario master capacitado para realizarlas.

   Las posibles vulnerabilidades del sistema mitigadas por BlueFingerprint son:
   -Suplantacion de identidad
   -Ataque de tipo man in the middle
   -Robo del token de verificacion de identidad
   -Robo de claves de sesion
   -Ataque a la integridad de las peticiones

*/
//Librerias de cifrado simetrico AES
#include <aes_keyschedule.h>
#include <bcal-cbc.h>
#include <aes_sbox.h>
#include <aes_types.h>
#include <blockcipher_descriptor.h>
#include <memxor.h>
#include <bcal_aes128.h>
#include <aes256_dec.h>
#include <aes_dec.h>
#include <aes_enc.h>
#include <bcal-ofb.h>
#include <aes_invsbox.h>
#include <aes192_enc.h>
#include <bcal-cmac.h>
#include <aes.h>
#include <bcal_aes256.h>
#include <keysize_descriptor.h>
#include <aes128_enc.h>
#include <bcal-basic.h>
#include <AESLib.h>
#include <aes128_dec.h>
#include <gf256mul.h>
#include <aes192_dec.h>
#include <bcal_aes192.h>
#include <aes256_enc.h>

//Librerias de comunicacion y gestion de memoria
#include <SoftwareSerial.h>
#include <SD.h>
#include <string.h>

//Constantes del programa
#define TAMANONOMBREMOVIL 40
#define TAMANOCLAVESIMETRICA 32
#define TAMANOMENSAJECIFRADO 256    //TODO
#define DIGITOSNUMEROAUTENTICACION 4
#define TAMANOLINEAFICHERO (TAMANONOMBREMOVIL + TAMANOCLAVESIMETRICA + 1)
#define RXBT 2
#define TXBT 3
//Variables globales
SoftwareSerial bluetooth(RXBT, TXBT);
File ficheroClaves;
uint8_t *claveSimetrica = malloc(TAMANOCLAVESIMETRICA*sizeof(uint8_t));
boolean primeraConexion;

//------------------------Funciones de proposito general-----------------------------
char *nextLine() {
  //Devuelve la siguiente linea del fichero o '\0' si es la ultima
  char linea[TAMANOLINEAFICHERO + 1] = "";
  if (ficheroClaves.read() == -1) {
    return '\0';
  }
  while (ficheroClaves.read() != "\n") {
    strcat(linea, ficheroClaves.peek());
  }
  return linea;
}
uint8_t *getClaveSimetrica(char *nombre) {
  char claveSimetrica[TAMANOCLAVESIMETRICA + 1];
  int linea = nombreEnFichero(nombre);
  if (nombre != -1) {
    ficheroClaves.close();
    ficheroClaves = SD.open("ficheroClaves.txt", "r");
    for (int i = 0; i < linea - 1; i++) {
      (void)nextLine();
    }
    strcpy(claveSimetrica, nextLine()[TAMANONOMBREMOVIL + 1]);
  }
  return (uint8_t *)claveSimetrica;
}
int cuentaLineas() {
  //Cuenta el numero de lineas del fichero de claves local
  ficheroClaves.close();
  ficheroClaves = SD.open("ficheroClaves.txt", "r");
  int nLineas = 0;
  while (ficheroClaves.read() != -1) {
    if (ficheroClaves.peek() == '\n') {
      nLineas ++;
    }
  }
  ficheroClaves.close();
  ficheroClaves = SD.open("ficheroClaves.txt", "r");
  return nLineas;
}
int nombreEnFichero(char *nombre) {
  //Devuelve el numero de linea en el que se encuentra el nombre si el nombre se encuentra en el fichero y -1 si no
  ficheroClaves.close();
  ficheroClaves = SD.open("ficheroClaves.txt", "r");
  boolean nombreEnFichero = true;
  char *lineaEnLectura = nextLine();
  int numeroDeLinea = 0;
  while (lineaEnLectura != '\0') {
    numeroDeLinea++;
    for (int i = 0; i < strlen(lineaEnLectura); i++) {
      if (nombre[0] == lineaEnLectura[i]) {
        nombreEnFichero = true;
        for (int j = 1; j < strlen(nombre); j++) {
          if (nombre[j] != lineaEnLectura[i + j]) {
            nombreEnFichero = false;
          }
        }
        if (nombreEnFichero == true) {
          return numeroDeLinea;
        }
      }
    }
    lineaEnLectura = nextLine();
  }
  return -1;
}

char *toString(int n) {
  //Fuente: https://www.systutorials.com/131/convert-string-to-int-and-reverse/
  int numDigitos = 1;
  int temp = n/10;
  while (temp != 0) {
    temp = n / 10;
    numDigitos++;
  }

  const char base_string[] = "";
  char out_string[numDigitos + 1];
  sprintf(out_string, "%s%d", base_string, n);
  return out_string;
}
//-----------------------Funciones relativas a la fase de la conexion----------------
int fase1() {
  //Devuelve el numero de autenticacion enviado al final de la fase 1 de conexion en plano o -1 si se aborto la conexion
  //Recibe por BT el nombre del movil que solicita la conexion y envia por BT el numero de autenticacion para la conexion cifrado con su clave simetrica
  //si la conexion se permite o "NO" si la conexion se aborta
  Serial.println("---------Fase 1 de conexion---------");
  Serial.println("");
  char nombreMovil[TAMANONOMBREMOVIL + 1];
  int contador = 0;

  while (true) {
    if (bluetooth.available() > 0) {
      Serial.println("Bluetooth recibiendo");
      char caracterEnLectura = bluetooth.read();
      Serial.println(caracterEnLectura);

      while (contador < TAMANONOMBREMOVIL && caracterEnLectura != '\0') {   //Arduino recibe nombre del movil
        nombreMovil[contador] = caracterEnLectura;
        contador ++;
        caracterEnLectura = bluetooth.read();
        Serial.println(caracterEnLectura);
      }
      Serial.print(nombreMovil);
      Serial.println(" solicita conexion");

      if (nombreEnFichero(nombreMovil) != -1) {       //Arduino comprueba que el movil esta en el fichero de nombres
        claveSimetrica = getClaveSimetrica(nombreMovil);
        Serial.print(nombreMovil);
        Serial.println(" SI se encuentra en fichero");
        int numeroDeAutenticacion = (int)random(pow(10, DIGITOSNUMEROAUTENTICACION));  //Arduino envia numero de autenticacion de identidad de movil en plano
        char *numeroDeAutenticacionCifrado = toString(numeroDeAutenticacion);
        aes256_enc_single(claveSimetrica, numeroDeAutenticacionCifrado);
        bluetooth.write(numeroDeAutenticacionCifrado);

        return numeroDeAutenticacion;
      } else {
        //Nombre no esta en fichero
        Serial.print(nombreMovil);
        Serial.println(" NO se encuentra en fichero");
        bluetooth.write("NO");

        return -1;
      }
    }
  }
}
boolean fase2(int numeroDeAutenticacion) {
  //Autentica la identidad del movil
  //Recibe por BT el numero de autenticacion cifrado con la clave simetrica del movil que solicita la conexion
  //Envia por BT "OK" o "NO" en funcion de si la conexion se aborto o no
  //Devuelve true si la conexion continua, false si se aborta
  char *numeroDeAutenticacionPlano = toString(numeroDeAutenticacion);
  char numeroDeAutenticacionCifrado[TAMANOMENSAJECIFRADO + 1];
  int contador = 0;
  Serial.println("---------Fase 2 de conexion---------");
  Serial.println("");

  while (true) {
    if (bluetooth.available() > 0) {
      char caracterEnLectura = bluetooth.read();

      while (contador < TAMANOMENSAJECIFRADO && caracterEnLectura != '\0') {   //Arduino recibe nombre del movil
        numeroDeAutenticacionCifrado[contador] = caracterEnLectura;
        contador ++;
        caracterEnLectura = bluetooth.read();
      }

      aes256_dec_single(claveSimetrica, numeroDeAutenticacionCifrado);
      if (strcmp(numeroDeAutenticacionCifrado, numeroDeAutenticacionPlano) == 0) {
        //Autenticado
        bluetooth.write("OK");
        Serial.println("Identidad confirmada");
        return true;
      } else {
        //Falso
        bluetooth.write("NO");
        Serial.println("Identidad falsa. Abortando conexion");
        return false;
      }
    }
  }
}
char fase3() {
  //Devuelve un caracter que representa el modo de trabajo del Arduino
  /*Codigo de recepcion por BT:

     '0': Modo open
     '1': Modo show user list
     '2': Modo delete user
     '3': Modo add user

  */
  //Envia por BT "OK" cuando accede al modo solicitado
  Serial.println("---------Fase 3 de conexion---------");
  Serial.println("");
  while (true) {
    if (bluetooth.available() > 0) {
      switch (bluetooth.read()) {
        case '0':
          bluetooth.write("OK");
          Serial.println("Entrando en modo open");
          return '0';
        case '1':
          bluetooth.write("OK");

          Serial.println("Entrando en modo show user list");
          return '1';

        case '2':
          bluetooth.write("OK");

          Serial.println("Entrando en modo delete user");
          return '2';

        case '3':
          bluetooth.write("OK");

          Serial.println("Entrando en modo add user");
          return '3';
      }
    }
  }
}

void setup() {
  pinMode(RXBT,INPUT);
  pinMode(TXBT, OUTPUT);
  Serial.begin(9600);
  Serial.println("Inicializada comunicacion");
  SD.begin();
  Serial.println("Inicializada tarjeta SD");
  bluetooth.begin(9600);
  Serial.println("Inicializado modulo Bluetooth");

  ficheroClaves = SD.open("ficheroClaves.txt", "r");
  primeraConexion = false;
  if (ficheroClaves.size() == 0 || cuentaLineas() == 1) {
    primeraConexion = true;
  }
}

void loop() {
  //Establecimiento de conexion en fase 1 y fase 2
  int numeroDeAutenticacion = fase1();
  if (numeroDeAutenticacion != -1) {  //Enviado "OK" en fase 1 de conexion
    boolean continuar = fase2((numeroDeAutenticacion + 1) % ((int)pow(10, DIGITOSNUMEROAUTENTICACION)));
    if (continuar == true) {  //Enviado "OK" en fase 2 de conexion. Conexion establecida.
      //Seleccion de modo de trabajo en fase 3
      char modoDeTrabajo = fase3();

      switch (modoDeTrabajo) {
        case '0':
          break;
        case '1':
          break;
        case '2':
          break;
        case '3':
          break;
      }

    } else {    //Enviado "NO" en fase 2 de conexion
      Serial.println("");
      Serial.println("----------------------REINICIO DE CONEXION-------------------");
      Serial.println("");
    }

  }
  else {    //Enviado "NO" en fase 1 de conexion
    Serial.println("");
    Serial.println("----------------------REINICIO DE CONEXION-------------------");
    Serial.println("");
  }
}
