package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class BtrSyncStoreTest {
    @Test
    fun changedResponseBecomesSnapshot() {
        val response = BtrSyncResponse(
            changed = true,
            version = "btr-ro-test",
            count = 1,
            manifests = listOf(
                BtrManifest(
                    manifestId = "yoxo",
                    displayName = "YOXO",
                    officialDomains = listOf("yoxo.ro"),
                    neverAsks = listOf("otp")
                )
            )
        )

        val snapshot = BtrSyncSnapshot.fromResponse(response, existing = null)

        assertNotNull(snapshot)
        assertEquals("btr-ro-test", snapshot?.version)
        assertEquals("yoxo.ro", snapshot?.manifests?.first()?.officialDomains?.first())
    }

    @Test
    fun unchangedResponseKeepsExistingSnapshot() {
        val existing = BtrSyncSnapshot(
            version = "btr-ro-test",
            generatedAt = "2026-06-13T00:00:00Z",
            manifests = listOf(BtrManifest(manifestId = "bt", displayName = "BT"))
        )
        val response = BtrSyncResponse(changed = false, version = "btr-ro-test", count = 0, manifests = null)

        val snapshot = BtrSyncSnapshot.fromResponse(response, existing = existing)

        assertEquals(existing, snapshot)
    }
}
