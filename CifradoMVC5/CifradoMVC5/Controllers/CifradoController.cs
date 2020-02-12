using CifradoMVC5.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace CifradoMVC5.Controllers
{
    public class CifradoController : Controller
    {
        // GET: SinRetorno
        public ActionResult SinRetorno()
        {
            return View();
        }

        // POST: SinRetorno
        [HttpPost]
        public ActionResult SinRetorno(String mensaje, String accion, String sha1, String md5, String sha256, String sha512)
        {
            // Si la accion es cifrar
            if(accion == "cifrar")
            {
                // Guardamos en un ViewBag el mensaje introducido
                ViewBag.Mensaje = mensaje;
                // Devolvemos a la vista la lista de Strings con los cifrados
                return View(CypherHelper.CifradoHash(mensaje));
            // Si la acción es comparar
            }else if(accion == "comparar")
            {
                // Guardamos en un ViewBag el mensaje introducido
                ViewBag.Mensaje = mensaje;
                // Instanciamos una lista de Strings para guardar los cifrados de la vista
                List<String> textoscifrados = new List<String>();
                textoscifrados.Add(sha1);
                textoscifrados.Add(md5);
                textoscifrados.Add(sha256);
                textoscifrados.Add(sha512);
                // Guardamos en ViewBag.Resultados los textos de "Es correcto" o "No coinciden" obtenidos del método CompararTexto
                ViewBag.Resultados = CypherHelper.CompararTexto(mensaje, textoscifrados);
                // Devolvemos los cifrados anteriores
                return View(textoscifrados);
            }
            return View();
        }

        // GET: SinRetornoSalt
        public ActionResult SinRetornoSalt()
        {
            return View();
        }

        // POST: SinRetornoSalt
        [HttpPost]
        public ActionResult SinRetornoSalt(String texto, String accion, String salt, String sha1, String md5, String sha256, String sha512)
        {
            // Si la acción es cifrar
            if (accion == "cifrar")
            {
                // Llamamos al método que genera el salt aleatorio. Podemos introducirle los caracteres que tendrá.
                salt = CypherHelper.GenerarSalt(25);
                // Concatenamos el salt al texto introducido
                String txtACifrar = texto + salt;
                // Guardamos el texto y el salt en ViewBags para poder mostrarlos en la Vista.
                ViewBag.Mensaje = texto;
                ViewBag.Salt = salt;
                // Devolvemos los textos cifrados generados por el texto mas el salt
                return View(CypherHelper.CifradoHash(txtACifrar));
            }
            // Si la accion es comparar
            else if (accion == "comparar")
            {
                // Concatenamos el texto introducido por el salt generado en el último cifrado realizado
                String txtACifrar = texto + salt;
                // Guardamos el texto y el salt en ViewBags para poder mostrarlos en la Vista
                ViewBag.Mensaje = texto;
                ViewBag.Salt = salt;
                // Instanciamos una lista de Strings para guardar los textos cifrados del último cifrado realizado
                List<String> textoscifrados = new List<String>();
                textoscifrados.Add(sha1);
                textoscifrados.Add(md5);
                textoscifrados.Add(sha256);
                textoscifrados.Add(sha512);
                // Guardamos en el ViewBag si coinciden o no los textos cifrados
                ViewBag.Resultados = CypherHelper.CompararTexto(txtACifrar, textoscifrados);
                // Devolvemos en el Model los textos cifrados del último cifrado
                return View(textoscifrados);
            }
            return View();
        }

        // GET: CifradoRinjdael
        public ActionResult CifradoRijndael()
        {
            return View();
        }

        // POST: CifradoRinjdael
        [HttpPost]
        public ActionResult CifradoRijndael(String texto, String clave, String textocifrado, String accion)
        {
            byte[] clavebyte = new PasswordDeriveBytes(clave, null).GetBytes(32);
            String mensaje = null;
            switch (accion)
            {
                case "cifrar":
                    mensaje = CypherHelper.CifrarTexto(texto, clavebyte);
                    break;
                case "descifrar":
                    byte[] textobytes = Encoding.Default.GetBytes(textocifrado);
                    mensaje = CypherHelper.DescifrarTexto(textobytes, clavebyte);
                    break;
                default:
                    break;
            }
            ViewBag.Mensaje = mensaje;
            return View();
        }

    }
}