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
#include <SD.h>
#include <string.h>

//Constantes del programa
#define TAMANONOMBREMOVIL 6
#define TAMANOCLAVESIMETRICA 32
#define TAMANOMENSAJECIFRADO 256    //TODO
#define DIGITOSNUMEROAUTENTICACION 4
#define TAMANOLINEAFICHERO (TAMANONOMBREMOVIL + TAMANOCLAVESIMETRICA + 1)

//Variables globales
File ficheroClaves;
uint8_t *claveSimetrica = malloc(TAMANOCLAVESIMETRICA*sizeof(uint8_t));

//------------------------Funciones de proposito general-----------------------------
//Funciones de formato

char *aArrayDeCaracteres(String s) {
  //Fuente: https://www.geeksforgeeks.org/convert-string-char-array-cpp/
  // assigning value to string s

  int n = s.length();

  // declaring character array
  char char_array[n + 1];

  // copying the contents of the
  // string to char array
  strcpy(char_array, s.c_str());

  return char_array;

}
//Funciones de manipulacion de fichero global de claves
String nextLine() {
  //Devuelve la siguiente linea del fichero o '\0' si es la ultima
  String linea;
  if (!ficheroClaves.available() ) {
    return '\0';
  }
  char temp = (char)ficheroClaves.read();
  while (ficheroClaves.available() &&  temp != '\n') {
    linea += temp;
    temp = (char)ficheroClaves.read();
  }
 
  return linea;
}
int nombreEnFichero(String nombre) {
  //Devuelve el numero de linea en el que se encuentra el nombre si el nombre se encuentra en el fichero y -1 si no
  ficheroClaves.close();
  ficheroClaves = SD.open("hola.txt");
  String lineaEnLectura = nextLine();
  int numeroDeLinea = 0;
  while (ficheroClaves.available()) {
    numeroDeLinea++;

    for (int i = 0; i < lineaEnLectura.length() - 1; i++) {

      if (lineaEnLectura.length() - 1 != nombre.length()-1) {
        break;
      }
      if (lineaEnLectura[i] != nombre[i]) {
        break;
      } else {
        if (i == lineaEnLectura.length() - 2) {
          return numeroDeLinea;
        }
      }
    }
    lineaEnLectura = nextLine();
    ficheroClaves.close();
  }
  return -1;
}
uint8_t *getClaveSimetrica(String nombre) {
  
  String claveSimetrica;
  int linea = nombreEnFichero(nombre);
  ficheroClaves = SD.open("hola.txt");
  for(int i = 0; i<linea; i++){
    nextLine();
    }
    
  claveSimetrica = nextLine();
  claveSimetrica += ',';
  Serial.println(claveSimetrica);
  String temp="" ;
  int contador = 0;
  uint8_t devolver[TAMANOCLAVESIMETRICA];
  for(int i = 0; i< claveSimetrica.length();i++){
    if(claveSimetrica[i] != ','){
      temp += claveSimetrica[i];
      }else{
        devolver[contador] = (uint8_t)temp.toInt();
        contador++;
        temp="";
        }
    }
    
  return devolver;
}

void setClaveSimetrica(String nombre, uint8_t *clave) {
  int linea = nombreEnFichero(nombre);
  ficheroClaves = SD.open("hola.txt", FILE_WRITE);
  ficheroClaves.print("master\n");
  String cad;
  Serial.print("master\n");
  for(int i=0;i< TAMANOCLAVESIMETRICA;i++){
          cad=(String)clave[i];
          ficheroClaves.print(cad+",");
          Serial.print(cad);
      }
      ficheroClaves.print(',');
  
  ficheroClaves.print("\n");
  ficheroClaves.close();
}

uint8_t *claveAleatoria() {
  uint8_t clave[TAMANOCLAVESIMETRICA];
  uint8_t claveTemp;
  for (int i = 0; i < TAMANOCLAVESIMETRICA; i++) {
    clave[i] = (uint8_t)random(0, 256);
  }
 
  return clave;
}

int cuentaLineas() {
  //Cuenta el numero de lineas del fichero de claves local
  ficheroClaves.close();
  ficheroClaves = SD.open("hola.txt");
  int nLineas = 0;
  while (ficheroClaves.read() != -1) {
    if ((char)ficheroClaves.peek() == '\n') {
      nLineas ++;
    }
  }
  ficheroClaves.close();
  ficheroClaves = SD.open("hola.txt");
  return nLineas;
}

//Funciones de comunicacion serial
void envia(int cadena) {
  Serial.print(cadena);
  Serial.println("#");
}
void imprime(int cadena) {
  Serial.println(cadena);
}
void envia(char *cadena) {
  Serial.print(cadena);
  Serial.println("#");
}
void imprime(char *cadena) {
  Serial.println(cadena);
}
void envia(String cadena) {
  Serial.print(cadena);
  Serial.println("#");
}
void imprime(String cadena) {
  Serial.println(cadena);
}
//-----------------------Funciones relativas a la fase de la conexion----------------
void primeraConexion() {
  randomSeed(analogRead(A0));
  uint8_t clave[TAMANOCLAVESIMETRICA];
  int temp;
  while (true) {
    if (Serial.available()) {
    
        for (int i = 0; i < TAMANOCLAVESIMETRICA; i++) {
          clave[i] =random(0, 256);
        } 
      setClaveSimetrica("master", clave);
      /*
      ficheroClaves = SD.open("hola.txt", FILE_WRITE);
      ficheroClaves.write("\nmaster\n");
      ficheroClaves.flush();
      
          
          for (int i = 0; i < TAMANOCLAVESIMETRICA; i++) {
            //imprime((int)clave[i]);
          }
          
      String cad;
      for(int i=0;i< TAMANOCLAVESIMETRICA;i++){
          cad=(String)clave[i];
          ficheroClaves.print(cad+" ");
          Serial.println(cad);
      }
      ficheroClaves.write("\n");
      ficheroClaves.close();
      */
      break;
    }
  }
}
int fase1() {
  //Devuelve el numero de autenticacion enviado al final de la fase 1 de conexion en plano o -1 si se aborto la conexion
  //Recibe por BT el nombre del movil que solicita la conexion y envia por BT el numero de autenticacion para la conexion cifrado con su clave simetrica
  //si la conexion se permite o "NO" si la conexion se aborta
  //imprime("---------Fase 1 de conexion---------");
  //imprime("");
  String nombreMovil;//[TAMANONOMBREMOVIL + 1];
  int contador = 0;

  while (true) {
    if (Serial.available()) {
      delay(50);
      //imprime("Bluetooth recibiendo");
      char caracterEnLectura = Serial.read();
      //imprime(caracterEnLectura);

      while (contador < TAMANONOMBREMOVIL && caracterEnLectura != '\0') {   //Arduino recibe nombre del movil
        nombreMovil += caracterEnLectura;
        contador ++;
        delay(100);
        caracterEnLectura = Serial.read();
        //imprime(caracterEnLectura);
      }
      Serial.print("NombreMovil: ");
      imprime(nombreMovil);
      ficheroClaves = SD.open("hola.txt");

      //imprime(" solicita conexion");

      if (nombreEnFichero(nombreMovil) != -1) {       //Arduino comprueba que el movil esta en el fichero de nombres
        Serial.print("Esta registrado ");
        claveSimetrica = getClaveSimetrica(nombreMovil);
        //imprime(nombreMovil);
        //imprime(" SI se encuentra en fichero");
        Serial.println("Llegue"+(String)(int)pow(10, DIGITOSNUMEROAUTENTICACION));
        randomSeed(analogRead(A0));
        int numeroDeAutenticacion = random(0,(int)pow(10, DIGITOSNUMEROAUTENTICACION));  //Arduino envia numero de autenticacion de identidad de movil en plano
        Serial.println("Random: "+(String)numeroDeAutenticacion);
        char numeroDeAutenticacionCifrado [4];
        int temp = numeroDeAutenticacion;
        for(int i = DIGITOSNUMEROAUTENTICACION-1; i>-1;i--){
        temp = temp %10;
        numeroDeAutenticacionCifrado[i]=(char)(temp+ ((int)'0'));
        }
        
        aes256_enc_single(claveSimetrica, numeroDeAutenticacionCifrado);
        //envia((String)numeroDeAutenticacionCifrado);
        Serial.println("Cifrado: "+(String)numeroDeAutenticacionCifrado);
        aes256_dec_single(claveSimetrica, numeroDeAutenticacionCifrado);
        Serial.println("Sin cifrar "+(String)numeroDeAutenticacionCifrado);
        return numeroDeAutenticacion;
      } else {
        //Nombre no esta en fichero
        //imprime(nombreMovil);
        //imprime(" NO se encuentra en fichero");
        envia("NO");

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
  char *numeroDeAutenticacionPlano = (char *)(numeroDeAutenticacion);
  char numeroDeAutenticacionCifrado[TAMANOMENSAJECIFRADO + 1];
  int contador = 0;
  //imprime("---------Fase 2 de conexion---------");
  //imprime("");

  while (true) {
    if (Serial.available() > 0) {
      char caracterEnLectura = Serial.read();

      while (contador < TAMANOMENSAJECIFRADO && caracterEnLectura != '\0') {   //Arduino recibe nombre del movil
        numeroDeAutenticacionCifrado[contador] = caracterEnLectura;
        contador ++;
        caracterEnLectura = Serial.read();
      }

//      aes256_dec_single(claveSimetrica, numeroDeAutenticacionCifrado);
      if (strcmp(numeroDeAutenticacionCifrado, numeroDeAutenticacionPlano) == 0) {
        //Autenticado
        envia("OK");
        //imprime("Identidad confirmada");
        return true;
      } else {
        //Falso
        envia("NO");
        //imprime("Identidad falsa. Abortando conexion");
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
  //imprime("---------Fase 3 de conexion---------");
  //imprime("");
  while (true) {
    if (Serial.available() > 0) {
      switch (Serial.read()) {
        case '0':
          envia("OK");
          //imprime("Entrando en modo open");
          return '0';
        case '1':
          envia("OK");

          //imprime("Entrando en modo show user list");
          return '1';

        case '2':
          envia("OK");

          //imprime("Entrando en modo delete user");
          return '2';

        case '3':
          envia("OK");

          //imprime("Entrando en modo add user");
          return '3';
      }
    }
  }
}

void setup() {
  Serial.begin(9600);
  //imprime("Inicializada comunicacion");
  if (!SD.begin(53))
  {
    Serial.println(F("Error al iniciar"));
    return;
  }
  //imprime("Inicializada tarjeta SD");

  //imprime(ficheroClaves.size());
  if (!SD.exists("hola.txt")) {
    primeraConexion();
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
      //imprime("");
      //imprime("----------------------REINICIO DE CONEXION-------------------");
      //imprime("");
    }

  }
  else {    //Enviado "NO" en fase 1 de conexion
    //imprime("");
    //imprime("----------------------REINICIO DE CONEXION-------------------");
    //imprime("");
  }
}
