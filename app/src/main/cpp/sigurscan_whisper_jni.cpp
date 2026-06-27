#include <jni.h>
#include <android/log.h>

#include <mutex>
#include <string>
#include <vector>

#include "whisper.h"

namespace {

constexpr const char * kLogTag = "SigurScanWhisper";
constexpr int kRequiredSampleRateHz = 16000;

std::mutex g_ctx_mutex;
std::string g_model_path;
whisper_context * g_ctx = nullptr;

std::string jstring_to_string(JNIEnv * env, jstring value) {
    if (value == nullptr) {
        return "";
    }
    const char * chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) {
        return "";
    }
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

std::vector<float> pcm16_to_float(JNIEnv * env, jshortArray pcm16) {
    const jsize length = env->GetArrayLength(pcm16);
    std::vector<jshort> pcm(length);
    env->GetShortArrayRegion(pcm16, 0, length, pcm.data());

    std::vector<float> pcmf32(length);
    for (jsize i = 0; i < length; ++i) {
        pcmf32[i] = static_cast<float>(pcm[i]) / 32768.0f;
    }
    return pcmf32;
}

jstring empty_string(JNIEnv * env) {
    return env->NewStringUTF("");
}

jstring string_from_utf8_bytes(JNIEnv * env, const std::string & value) {
    if (value.empty()) {
        return empty_string(env);
    }

    jbyteArray bytes = env->NewByteArray(static_cast<jsize>(value.size()));
    if (bytes == nullptr) {
        return empty_string(env);
    }
    env->SetByteArrayRegion(
        bytes,
        0,
        static_cast<jsize>(value.size()),
        reinterpret_cast<const jbyte *>(value.data())
    );

    jclass string_class = env->FindClass("java/lang/String");
    jmethodID constructor = string_class == nullptr
        ? nullptr
        : env->GetMethodID(string_class, "<init>", "([BLjava/lang/String;)V");
    jstring charset = env->NewStringUTF("UTF-8");
    jobject result = nullptr;
    if (constructor != nullptr && charset != nullptr) {
        result = env->NewObject(string_class, constructor, bytes, charset);
    }

    env->DeleteLocalRef(bytes);
    if (charset != nullptr) {
        env->DeleteLocalRef(charset);
    }
    if (string_class != nullptr) {
        env->DeleteLocalRef(string_class);
    }

    return result == nullptr ? empty_string(env) : static_cast<jstring>(result);
}

whisper_context * get_or_load_context_locked(const std::string & model_path) {
    if (g_ctx != nullptr && g_model_path == model_path) {
        return g_ctx;
    }
    if (g_ctx != nullptr) {
        whisper_free(g_ctx);
        g_ctx = nullptr;
        g_model_path.clear();
    }

    whisper_context_params cparams = whisper_context_default_params();
    cparams.use_gpu = false;
    g_ctx = whisper_init_from_file_with_params(model_path.c_str(), cparams);
    if (g_ctx != nullptr) {
        g_model_path = model_path;
    }
    return g_ctx;
}

} // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_ro_sigurscan_app_WhisperCppNativeBridge_nativeIsReady(JNIEnv *, jobject) {
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_ro_sigurscan_app_WhisperCppNativeBridge_nativeCanLoadModel(
    JNIEnv * env,
    jobject,
    jstring model_path
) {
    const std::string model_path_str = jstring_to_string(env, model_path);
    if (model_path_str.empty()) {
        return JNI_FALSE;
    }

    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    return get_or_load_context_locked(model_path_str) == nullptr ? JNI_FALSE : JNI_TRUE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_ro_sigurscan_app_WhisperCppNativeBridge_nativeTranscribe(
    JNIEnv * env,
    jobject,
    jshortArray pcm16_mono,
    jint sample_rate_hz,
    jstring language,
    jstring model_path
) {
    if (pcm16_mono == nullptr || sample_rate_hz != kRequiredSampleRateHz) {
        return empty_string(env);
    }

    const std::string model_path_str = jstring_to_string(env, model_path);
    if (model_path_str.empty()) {
        __android_log_write(ANDROID_LOG_WARN, kLogTag, "model_path_missing");
        return empty_string(env);
    }

    const std::string language_str = jstring_to_string(env, language);
    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    whisper_context * ctx = get_or_load_context_locked(model_path_str);
    if (ctx == nullptr) {
        __android_log_write(ANDROID_LOG_ERROR, kLogTag, "model_load_failed");
        return empty_string(env);
    }

    std::vector<float> pcmf32 = pcm16_to_float(env, pcm16_mono);
    whisper_full_params params = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);
    params.n_threads = 4;
    params.duration_ms = static_cast<int>((static_cast<int64_t>(pcmf32.size()) * 1000) / sample_rate_hz);
    params.print_realtime = false;
    params.print_progress = false;
    params.print_timestamps = false;
    params.print_special = false;
    params.translate = false;
    params.no_context = true;
    params.no_timestamps = true;
    params.single_segment = true;
    params.max_tokens = 32;
    params.audio_ctx = 256;
    params.language = language_str.empty() ? "ro" : language_str.c_str();

    if (whisper_full(ctx, params, pcmf32.data(), static_cast<int>(pcmf32.size())) != 0) {
        __android_log_write(ANDROID_LOG_ERROR, kLogTag, "transcription_failed");
        return empty_string(env);
    }

    std::string transcript;
    const int segments = whisper_full_n_segments(ctx);
    for (int i = 0; i < segments; ++i) {
        const char * text = whisper_full_get_segment_text(ctx, i);
        if (text != nullptr) {
            transcript += text;
        }
    }
    return string_from_utf8_bytes(env, transcript);
}
