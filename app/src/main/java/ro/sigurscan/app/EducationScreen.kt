package ro.sigurscan.app

import android.Manifest
import android.app.role.RoleManager
import android.content.Intent
import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS
import android.text.Html
import android.text.Spanned
import android.util.Log
import android.view.ViewGroup.LayoutParams
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn as AndroidxOptIn
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview as CameraPreview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.compose.ui.platform.LocalLifecycleOwner
import coil.compose.SubcomposeAsyncImage
import ro.sigurscan.app.ui.theme.SigurScanTheme
import ro.sigurscan.app.ui.theme.SigurColors
import org.json.JSONArray
import org.json.JSONObject
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.common.InputImage
import java.text.SimpleDateFormat
import java.io.File
import java.util.*
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

internal data class LessonContent(
    val id: String,
    val title: String,
    val summary: String,
    val question: String,
    val options: List<String>,
    val correctIndex: Int
)

@Composable
fun EducationTab(viewModel: ScannerViewModel) {
    val lessons = listOf(
        LessonContent(
            id = "lesson_phishing_sms",
            title = "Cum identifici un link din SMS",
            summary = "Nu apăsa pe linkul din mesaj înainte să verifici sursa.",
            question = "Ce faci dacă mesajul conține un link cu urgență, dar nu recunoști expeditorul?",
            options = listOf(
                "Ceri pe cineva să-l verifice și nu deschizi linkul",
                "Deschizi imediat, poate e urgent",
                "Ceri 2FA prin SMS pentru siguranță"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_mail_links",
            title = "Mesaj email + butoane suspecte",
            summary = "Butonul afișat poate ascunde un link către alt domeniu.",
            question = "Ce e corect când vezi un buton „Click aici”?",
            options = listOf(
                "Verifici adresa reală din atributul link-ului înainte de apăsare",
                "Dai click doar pe textul clar de pe buton",
                "Copiezi adresa din semnătura emailului"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_qr_security",
            title = "QR în phishing",
            summary = "Codurile QR pot duce la aceeași pagină rău intenționată ca și linkurile text.",
            question = "Ce faci dacă ți se cere scanare QR de la un mesaj nediagnosticat?",
            options = listOf(
                "Nu-l scanezi și anunți emitentul pe canal oficial",
                "Scanezi, dar cu Wi-Fi oprit",
                "Scanezi doar dacă mesajul pare urgent"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_courier_alert",
            title = "Pachete reținute sau AWB incorect",
            summary = "Frauda de tip curier cere adesea o taxă de eliberare prin link-uri neoficiale.",
            question = "Ce faci când primești mesaj că livrarea e blocată și ți se cere plată urgentă?",
            options = listOf(
                "Verifici AWB-ul direct pe site-ul oficial al curierului",
                "Deschizi linkul din mesajul primit",
                "Confirmezi datele cardului în formularul din SMS"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_anaf_scam",
            title = "Mesaje cu ANAF/TVA fals",
            summary = "ANAF nu cere plăți directe prin linkuri din SMS sau emailuri improvizate.",
            question = "Dacă vezi o notificare cu rambursare/penalizare fiscală care cere acces la cont, ce faci?",
            options = listOf(
                "Verifici direct în portalul oficial ANAF, nu din linkul primit",
                "Intrii pe link și confirmi datele persoanele",
                "Descarci toate atașamentele ca să te asiguri"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_olx_card",
            title = "Oferte OLX/card și vouchere",
            summary = "Cererea de date bancare prin link rapid este frecventă pe platforme de falsă ofertă.",
            question = "Care e regula sigură la o ofertă mare 'gratuită' primită prin mesaj?",
            options = listOf(
                "Verifici oferta în aplicația oficială a platformei fără a da date sensibile",
                "Folosești linkul imediat și apoi schimbi parola dacă e nevoie",
                "Scanezi eventualele atașamente PDF ca să confirmi autentificitatea"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_crypto_deepfake",
            title = "Crypto/Deepfake și promisiuni false",
            summary = "Promisiunile de profit rapid sau investiții instant vizează panicarea rapidă.",
            question = "Cum reduci riscul la astfel de mesaje?",
            options = listOf(
                "Ignori promisiunile, verifici sursa oficială și eviți orice achiziție prin link",
                "Cerzi un credit mic ca test înainte de a da datele",
                "Te uiți pe link dintr-un browser privat fără alt control"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_parental_protection",
            title = "Protecția părinților online",
            summary = "Persoanele mai puțin tehnice sunt ținta preferată a mesajelor de phishing.",
            question = "Ce faci dacă părintelui i se cere verificarea contului printr-un link nou?",
            options = listOf(
                "Discuți împreună pe un apel separat și nu acționezi pe acel link",
                "Îl ajuți să dea click dacă nu ai timp să verifici",
                "Îi setezi parole noi pe acel site imediat"
            ),
            correctIndex = 0
        )
    )

    var selectedLesson by remember { mutableStateOf(lessons.first()) }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp)) {
        Text("Educație", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(8.dp))
        Text("Alege o lecție, vezi regula și apoi verifici cu un mini test.", color = SigurColors.TextSecondary, fontSize = 12.sp)

        Spacer(modifier = Modifier.height(16.dp))

        lessons.forEach { lesson ->
            val isSelected = selectedLesson.id == lesson.id
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
                    .clickable { selectedLesson = lesson },
                shape = DSCardShape,
                colors = CardDefaults.cardColors(containerColor = if (isSelected) SigurColors.BrandTint else SigurColors.BackgroundCard),
                border = BorderStroke(1.dp, if (isSelected) SigurColors.Brand else SigurColors.GlassBorder)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (viewModel.completedLessons.contains(lesson.id)) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                        }
                        Text(lesson.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    }
                    Text(lesson.summary, color = SigurColors.TextSecondary, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Card(
            shape = DSCardShape,
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            border = DSCardBorder
        ) {
            var answerFeedback by remember(selectedLesson.id) { mutableStateOf<String?>(null) }

            Column(modifier = Modifier.padding(16.dp)) {
                Text("Quiz: ${selectedLesson.title}", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(12.dp))
                Text(selectedLesson.question, color = SigurColors.TextSecondary)
                Spacer(modifier = Modifier.height(10.dp))

                selectedLesson.options.forEachIndexed { index, option ->
                    val isCorrect = answerFeedback != null && index == selectedLesson.correctIndex
                    val isWrong = answerFeedback == option && !isCorrect

                    Button(
                        onClick = {
                            answerFeedback = option
                            if (index == selectedLesson.correctIndex) {
                                viewModel.setLessonCompleted(selectedLesson.id)
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = when {
                                isCorrect -> SigurColors.SafeLight
                                isWrong -> SigurColors.DangerousLight
                                else -> SigurColors.BackgroundSurface
                            }
                        ),
                        shape = DSCardShape,
                        border = BorderStroke(1.dp, when {
                            isCorrect -> SigurColors.SafeBorder
                            isWrong -> SigurColors.DangerousBorder
                            else -> SigurColors.GlassBorder
                        })
                    ) {
                        Text(option, color = SigurColors.TextPrimary, fontSize = 12.sp, textAlign = TextAlign.Start)
                    }
                }

                if (answerFeedback != null) {
                    val selectedIndex = selectedLesson.options.indexOfFirst { it == answerFeedback }
                    if (selectedIndex == selectedLesson.correctIndex) {
                        Text("Corect. Ai înțeles pasul de bază.", color = SigurColors.Safe, modifier = Modifier.padding(top = 8.dp))
                    } else {
                        Text("Incorect. Răspunsul corect: ${selectedLesson.options[selectedLesson.correctIndex]}", color = SigurColors.Dangerous, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            }
        }
    }
}
