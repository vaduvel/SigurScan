package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P-RULES Felia 3 — device-side consumption of the rules manifest.
 *
 * The key gate: every backend manifest pattern (authored for Python `re`) must
 * compile in Java's regex engine, so the manifest can drive on-device detection
 * without a parity break. The bundled fixture is the same manifest the backend
 * serves at /v1/rules/sync.
 */
class RulesManifestConsumptionTest {

    private fun loadManifest(): RulesManifestDto {
        val stream = javaClass.classLoader!!.getResourceAsStream("scam_rules_manifest_v1.json")
        assertNotNull("manifest fixture missing", stream)
        val json = stream!!.bufferedReader().use { it.readText() }
        return Gson().fromJson(json, RulesManifestDto::class.java)
    }

    @Test
    fun everyBackendPatternCompilesInJavaRegex() {
        val matcher = RulesManifestMatcher(loadManifest())
        assertTrue(
            "Python-only patterns that Java cannot compile: ${matcher.unsupportedPatterns}",
            matcher.unsupportedPatterns.isEmpty()
        )
    }

    @Test
    fun matcherMatchesExpectedGroups() {
        val matcher = RulesManifestMatcher(loadManifest())
        assertTrue("SENSITIVE_CREDENTIAL_PATTERNS" in matcher.matchingGroups("introdu codul otp si cvv"))
        assertTrue("REMOTE_ACCESS_PATTERNS" in matcher.matchingGroups("instaleaza anydesk acum"))
        assertTrue("SENSITIVE_PAYMENT_PATTERNS" in matcher.matchingGroups("transfera banii in cont sigur"))
        assertTrue(matcher.matchingGroups("buna ziua, ne vedem maine la cafea").isEmpty())
        assertTrue(matcher.matchingGroups("").isEmpty())
    }

    @Test
    fun snapshotFromResponseIsVersionGated() {
        val existing = RulesManifestSnapshot("v1", RulesManifestDto(version = "v1"))
        // changed=false -> keep existing (no-op)
        val noop = RulesManifestSnapshot.fromResponse(
            RulesSyncResponse(changed = false, version = "v1"), existing
        )
        assertEquals(existing, noop)
        // changed=true with a manifest -> adopt the new one
        val updated = RulesManifestSnapshot.fromResponse(
            RulesSyncResponse(changed = true, version = "v2", manifest = RulesManifestDto(version = "v2")),
            existing
        )
        assertNotNull(updated)
        assertEquals("v2", updated!!.version)
        assertFalse(updated == existing)
    }
}
