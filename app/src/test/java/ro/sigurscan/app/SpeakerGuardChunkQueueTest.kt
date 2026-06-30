package ro.sigurscan.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test

class SpeakerGuardChunkQueueTest {
    @Test
    fun slowConsumerDoesNotBlockRecorderAndKeepsMostRecentAudio() = runBlocking {
        val queue = SpeakerGuardChunkQueue(capacity = 2)
        val received = mutableListOf<Int>()

        val consumer = launch(Dispatchers.Default) {
            delay(100)
            repeat(2) {
                val chunk = queue.receive()
                delay(25)
                received += chunk.first().toInt()
            }
        }

        withTimeout(50) {
            repeat(6) { index ->
                queue.send(shortArrayOf(index.toShort()))
            }
        }

        consumer.join()
        queue.close()

        assertEquals(listOf(4, 5), received)
        assertEquals(4, queue.chunksDropped)
    }
}
