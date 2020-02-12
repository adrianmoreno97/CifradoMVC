using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace CifradoMVC5.Helpers
{
    public class CypherHelper
    {
        // Con este método realizamos el cifrado sin retorno. Devuelve una lista de Strings con los resultados de cada tipo de cifrado utilizado-
        public static List<String> CifradoHash(String text)
        {
            // Instanciamos un conversor para convertir el String recibido en un array de bytes.
            UnicodeEncoding converter = new UnicodeEncoding();
            byte[] input = converter.GetBytes(text);
            List<String> output = new List<String>();
            // Tipos de cifrado a utilizar
            SHA1Managed sha1 = new SHA1Managed(); // No es recomendable.
            SHA256Managed sha256 = new SHA256Managed(); // Recomendado.
            MD5Cng md5 = new MD5Cng(); // No es recomendable.
            SHA512Managed sha512 = new SHA512Managed(); // Muy recomendado. Pero ocupa más espacio y puede ser más lento.
            // Añadimos los resultados a la lista de Strings
            output.Add(converter.GetString(sha1.ComputeHash(input)));
            output.Add(converter.GetString(md5.ComputeHash(input)));
            output.Add(converter.GetString(sha256.ComputeHash(input)));
            output.Add(converter.GetString(sha512.ComputeHash(input)));
            // Devolvemos la lista
            return output;
        }

        // Con este método comparamos si el texto introducido es el mismo que el anterior.
        // Para ello pedimos el texto introducido y los textos cifrados que se encuentren en la vista.
        public static List<String> CompararTexto(String text, List<String> textoscifrados)
        {
            List<String> resultados = new List<String>();
            // Guardamos en una lista de Strings los resultados del cifrado del texto introducido.
            List<String> textos = CypherHelper.CifradoHash(text);
            int contador = 0;
            // Por cada texto cifrado
            foreach(String txt in textos)
            {
                // Instanciamos el conversor para convertir a un array de bytes tanto el texto cifrado de la vista como el generado por el texto introducido.
                UnicodeEncoding converter = new UnicodeEncoding();
                byte[] arrayIntroducido = converter.GetBytes(txt);
                byte[] arrayAComparar = converter.GetBytes(textoscifrados[contador]);
                // Llamamos al método CompararBytes para ver si la longitud de los arrays así como cada byte coinciden con el tipo de cifrado usado.
                if (CypherHelper.CompararBytes(arrayIntroducido,arrayAComparar))
                {
                    // Si devuelve true, es correcto
                    resultados.Add("Es correcto");
                }
                else
                {
                    // Si no, los valores no coinciden
                    resultados.Add("No coincide");
                }
                contador++;
            }
            // Devolvemos la lista resultados
            return resultados;
        }

        // Con este método comparamos los dos arrays que reciben.
        private static bool CompararBytes(byte[] ar1, byte[] ar2)
        {
            // Si no coincide la longitud de los arrays devolvemos false
            if(ar1.Length != ar2.Length)
            {
                return false;
            }
            else
            {
                // Si no hacemos un bucle por cada posición del array para comparar los bytes
                for (int i = 0; i < ar1.Length; i++)
                {
                    // Mientras coincidan nunca entrará aqui.
                    if (!(ar1[i].Equals(ar2[i])))
                    {
                        // Si no coinciden, devolvemos false
                        return false;
                    }
                }
                // Si realiza todo el bucle devolvemos true.
                return true;
            }
        }

        // Con este método generamos un String aleatorio llamado Salt. Podemos escoger la cantidad de caractéres que tendrá el salt.
        public static String GenerarSalt(int iteraciones)
        {
            Random r = new Random();
            String salt = "";
            // Bucle para generar los caractéres del salt. n veces introducidas en la variable iteraciones
            for (int i = 1; i <= iteraciones; i++)
            {
                // Generamos un número aleatorio
                int aleatorio = r.Next(1, 255);
                // Obtenemos el valor de la letra en formato ASCII del número generado aleatoriamente
                char letra = Convert.ToChar(aleatorio);
                // Lo concatenamos al salt
                salt += letra;
            }
            // Devolvemos el salt
            return salt;
        }

        // Con este método ciframos el texto que introduzca el usuario y lo devolvemos
        public static String CifrarTexto(String texto, byte[] clave)
        {
            // Instanciamos el Rijndael
            Rijndael cifradoRijn = Rijndael.Create();
            byte[] encriptado = null;
            byte[] salida = null;
            try
            {
                // Asignamos en la clave del Rijndael la clave introducida por el usuario
                cifradoRijn.Key = clave;
                // Generamos un vector de inicialización
                cifradoRijn.GenerateIV();
                // Convertimos el texto introducido a un array de bytes
                byte[] entrada = Encoding.UTF8.GetBytes(texto);
                // Encriptamos el mensaje
                encriptado = cifradoRijn.CreateEncryptor().TransformFinalBlock(entrada, 0, entrada.Length);
                // Inicializamos un array de bytes con la longitud del mensaje encriptado y la longitud del vector de inicialización
                salida = new byte[cifradoRijn.IV.Length + encriptado.Length];
                // Copiamos el vector al principio del array salida
                cifradoRijn.IV.CopyTo(salida, 0);
                // Copiamos el mensaje encriptado en el array salida después del vector
                encriptado.CopyTo(salida, cifradoRijn.IV.Length);
            }
            catch (Exception)
            {
                throw new Exception("Error al cifrar los datos.");
            }
            finally
            {
                // Limpiamos el Rijndael
                cifradoRijn.Dispose();
                cifradoRijn.Clear();
            }
            // Convertimos el array de bytes salida a String
            String resultado = Encoding.Default.GetString(salida);
            // Devolvemos el resultado
            return resultado;
        }

        //Con este método usamos el mensaje cifrado y la clave introducida para descirar el mensaje
        public static String DescifrarTexto(byte[] entrada, byte[] clave)
        {
            // Instanciamos el Rijndael
            Rijndael cifradoRijn = Rijndael.Create();
            // Inicializamos un array temporal con la longitud del vector de inicialización
            byte[] arrayTemporal = new byte[cifradoRijn.IV.Length];
            // Inicializamos un array que tendrá la longitud del mensaje encriptado
            byte[] encriptado = new byte[entrada.Length - cifradoRijn.IV.Length];
            String textodescifrado = String.Empty;
            try
            {
                // Asignamos la clave
                cifradoRijn.Key = clave;
                // Copiamos en el array temporal el vector de inicialización
                Array.Copy(entrada, arrayTemporal, arrayTemporal.Length);
                // Copiamos el mensaje sin el vector de inicialización en un array
                Array.Copy(entrada, arrayTemporal.Length, encriptado, 0, encriptado.Length);
                // Asignamos el vector de inicialización
                cifradoRijn.IV = arrayTemporal;
                // Desencriptamos el mensaje
                byte[] prueba = cifradoRijn.CreateDecryptor().TransformFinalBlock(encriptado, 0, encriptado.Length);
                // Convertimos el mensaje descifrado a String
                textodescifrado = Encoding.UTF8.GetString(prueba);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
            finally
            {
                // Limpiamos el Rijndael
                cifradoRijn.Dispose();
                cifradoRijn.Clear();    
            }
            // Devolvemos el mensaje descifrado
            return textodescifrado;
        }
    }
}