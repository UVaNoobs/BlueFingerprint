package com.grg.bluetoothandroidarduino;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import static com.grg.bluetoothandroidarduino.DispositivosBT.EXTRA_DEVICE_ADDRESS;


//basado en http://www.innovadomotics.com/mn-tuto/mn-android/proyectos.html

public class UserInterface extends AppCompatActivity {

    //1)
    Button idEncender, idApagar,idDesconectar,imPepe;
    TextView idBufferIn,idControl;
    //-------------------------------------------
    Handler bluetoothIn;
    final int handlerState = 0;
    private BluetoothAdapter btAdapter = null;
    private BluetoothSocket btSocket = null;
    private StringBuilder DataStringIN = new StringBuilder();
    private ConnectedThread MyConexionBT;
    // Identificador unico de servicio - SPP UUID
    private static final UUID BTMODULEUUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    // String para la direccion MAC
    private  String address = null;
    public  String claveCifrada = "";
    private  char clave []={97,128,106, 207,215,88,124,188,15,165,80,167,128,157,12,169,151,42,80,41,80,84,45,43,91,10,165,25,238,52,238,172};
    public int x = 0;


    private String etTexto, etPassword;
    private TextView tvTexto;
    private Button btEncriptar, btDesEncriptar, btApiEncriptada;
    private String textoSalida;
    //-------------------------------------------

    public String apiKeyEncriptada ="0SPrEK0JntQ2qCm9cPEabw==";
    public String passwordEncriptacion = "gdsawr";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_user_interfaz);
        //2)
        //Enlaza los controles con sus respectivas vistas
        idEncender = (Button) findViewById(R.id.idEncender);
        //idApagar = (Button) findViewById(R.id.idApagar);
        idDesconectar = (Button) findViewById(R.id.idDesconectar);
        idBufferIn = (TextView) findViewById(R.id.idBufferIn);
        imPepe= (Button) findViewById(R.id.imPepe);
        idControl = (TextView) findViewById(R.id.idControl);




        //idQRGenerator = (Button) findViewById(R.id.idQRGenerator);

        String cifrado;
        bluetoothIn = new Handler() {
            public void handleMessage(Message msg) {

                if (msg.what == handlerState) {

                    String readMessage = (String) msg.obj;
                    /*if(claveCifrada.compareTo("CLAVE#")==0){
                        x=true;
                    }*/

                    DataStringIN.append(readMessage);

                    int endOfLineIndex = DataStringIN.indexOf("#");
                    String dataInPrint="";
                    if (endOfLineIndex > 0) {

                        //dataInPrint será el mensaje que nos han mandado
                        dataInPrint = DataStringIN.substring(0, endOfLineIndex);
                        Log.d("recibido: ",dataInPrint);
                        x++;
                        if(x==2){
                            claveCifrada=dataInPrint;
                            idControl.setText(claveCifrada);
                        };
                        idBufferIn.setText("Dato: " + dataInPrint);//<-<- PARTE A MODIFICAR >->->

                        /*if(x) {
                            idControl.setText(claveCifrada);
                            x=false;
                        }*/

                        DataStringIN.delete(0, DataStringIN.length());

                    }

                    //gestionar el mensaje recibido

                }
            }
        };

        etTexto = "1111";//claveCifrada;
        etPassword = "hola";
        tvTexto = findViewById(R.id.text);



        /*btEncriptar = findViewById(R.id.enc);
        btEncriptar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                etTexto = claveCifrada;
                etPassword = clave.toString();
                try{
                    textoSalida = encriptar(etTexto, etPassword);
                    tvTexto.setText(textoSalida);
                    Log.d("ENC", textoSalida);
                } catch (Exception e){
                    e.printStackTrace();
                }
            }
        });*/

        /*btDesEncriptar = findViewById(R.id.dec);
        btDesEncriptar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                etTexto = claveCifrada;
                etPassword = clave.toString();
                try{
                    textoSalida = desencriptar(claveCifrada, etPassword);
                    tvTexto.setText(textoSalida);
                    Log.d("DES", textoSalida);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        });
*/

        btAdapter = BluetoothAdapter.getDefaultAdapter(); // get Bluetooth adapter
        VerificarEstadoBT();




        // Configuracion onClick listeners para los botones
        // para indicar que se realizara cuando se detecte
        // el evento de Click
        imPepe.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                MyConexionBT.write("master");
                //excribe en idControl la password
                //password en claveCifrada

            }
        });

        idEncender.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v)
            {
                //Security.addProvider(new org.)
                int clave=Integer.parseInt(claveCifrada);
                clave ++;
                String respuesta=Integer.toString(clave);
                MyConexionBT.write(respuesta);
                tvTexto.setText("Enviado: "+respuesta);

            }
        });
/*
        idApagar.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {

                MyConexionBT.write("0");

            }
        });*/

        idDesconectar.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                if (btSocket!=null)
                {
                    try {btSocket.close();}
                    catch (IOException e)
                    { Toast.makeText(getBaseContext(), "Error", Toast.LENGTH_SHORT).show();;}
                }
                finish();
            }
        });

    }

    private String desencriptar(String datos, String password) throws Exception{
        SecretKeySpec secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] datosDescoficados = Base64.decode(datos, Base64.DEFAULT);
        byte[] datosDesencriptadosByte = cipher.doFinal(datosDescoficados);
        String datosDesencriptadosString = new String(datosDesencriptadosByte);
        return datosDesencriptadosString;
    }

    private String encriptar(String datos, String password) throws Exception{
        SecretKeySpec secretKey = generateKey(password);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] datosEncriptadosBytes = cipher.doFinal(datos.getBytes());
        String datosEncriptadosString = Base64.encodeToString(datosEncriptadosBytes, Base64.DEFAULT);
        return datosEncriptadosString;
    }

    private SecretKeySpec generateKey(String password) throws Exception{
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = password.getBytes("UTF-8");
        key = sha.digest(key);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        return secretKey;
    }

    private BluetoothSocket createBluetoothSocket(BluetoothDevice device) throws IOException
    {
        //crea un conexion de salida segura para el dispositivo
        //usando el servicio UUID
        return device.createRfcommSocketToServiceRecord(BTMODULEUUID);
    }

    @Override
    public void onResume()
    {
        super.onResume();
        //Consigue la direccion MAC desde DeviceListActivity via intent
        Intent intent = getIntent();
        //Consigue la direccion MAC desde DeviceListActivity via EXTRA
        address = intent.getStringExtra(EXTRA_DEVICE_ADDRESS);//<-<- PARTE A MODIFICAR >->->
        //Setea la direccion MAC
        BluetoothDevice device = btAdapter.getRemoteDevice(address);

        try
        {
            btSocket = createBluetoothSocket(device);
        } catch (IOException e) {
            Toast.makeText(getBaseContext(), "La creacción del Socket fallo", Toast.LENGTH_LONG).show();
        }
        // Establece la conexión con el socket Bluetooth.
        try
        {
            btSocket.connect();
        } catch (IOException e) {
            try {
                btSocket.close();
            } catch (IOException e2) {}
        }
        MyConexionBT = new ConnectedThread(btSocket);
        MyConexionBT.start();
    }

    @Override
    public void onPause()
    {
        super.onPause();
        try
        { // Cuando se sale de la aplicación esta parte permite
            // que no se deje abierto el socket
            btSocket.close();
        } catch (IOException e2) {}
    }

    //Comprueba que el dispositivo Bluetooth Bluetooth está disponible y solicita que se active si está desactivado
    private void VerificarEstadoBT() {

        if(btAdapter==null) {
            Toast.makeText(getBaseContext(), "El dispositivo no soporta bluetooth", Toast.LENGTH_LONG).show();
        } else {
            if (btAdapter.isEnabled()) {
            } else {
                Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
                startActivityForResult(enableBtIntent, 1);
            }
        }
    }

    //Crea la clase que permite crear el evento de conexion
    private class ConnectedThread extends Thread
    {
        private final InputStream mmInStream;
        private final OutputStream mmOutStream;

        public ConnectedThread(BluetoothSocket socket)
        {
            InputStream tmpIn = null;
            OutputStream tmpOut = null;
            try
            {
                tmpIn = socket.getInputStream();
                tmpOut = socket.getOutputStream();
            } catch (IOException e) { }
            mmInStream = tmpIn;
            mmOutStream = tmpOut;
        }

        public void run()
        {
            byte[] buffer = new byte[256];
            int bytes;

            // Se mantiene en modo escucha para determinar el ingreso de datos
            String readMessage="";
            while (true) {
                try {

                    bytes = mmInStream.read(buffer);
                    readMessage = new String(buffer, 0, bytes);
                    // Envia los datos obtenidos hacia el evento via handler
                    bluetoothIn.obtainMessage(handlerState, bytes, -1, readMessage).sendToTarget();


                } catch (IOException e) {
                    break;
                }
            }
            /*try {

                bytes = mmInStream.read(buffer);
                readMessage = new String(buffer, 0, bytes);
                // Envia los datos obtenidos hacia el evento via handler
                bluetoothIn.obtainMessage(handlerState, bytes, -1, readMessage).sendToTarget();
                idControl.setText(claveCifrada);


            } catch (IOException e) {

            }*/

        }
        //Envio de trama
        public void write(String input)
        {
            try {
                mmOutStream.write(input.getBytes());
            }
            catch (IOException e)
            {
                //si no es posible enviar datos se cierra la conexión
                Toast.makeText(getBaseContext(), "La Conexión fallo", Toast.LENGTH_LONG).show();
                finish();
            }
        }
    }
}