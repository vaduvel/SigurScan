# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Retrofit/Gson and the local persisted caches deserialize several Kotlin data
# classes reflectively, and not every field has an explicit @SerializedName yet.
# Keep the app package stable while still enabling R8/resource shrinking for the
# release pipeline; this avoids silent JSON contract regressions.
-keepattributes Signature,*Annotation*
-keep class ro.sigurscan.app.** { *; }
