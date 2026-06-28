package ro.sigurscan.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class SpeakerGuardChunkQueueTest {
    @Test
    fun slowConsumerReceivesAllChunksWithoutDroppingAudio() = runBlocking {
        val queue = SpeakerGuardChunkQueue(capacity = 2)
        val received = mutableListOf<Int>()

        val consumer = launch(Dispatchers.Default) {
            repeat(6) {
                val chunk = queue.receive()
                delay(25)
                received += chunk.first().toInt()
            }
        }
        val producer = async(Dispatchers.Default) {
            repeat(6) { index ->
                queue.send(shortArrayOf(index.toShort()))
            }
        }

        producer.await()
        consumer.join()
        queue.close()

        assertEquals(listOf(0, 1, 2, 3, 4, 5), received)
        assertEquals(0, queue.chunksDropped)
    }
}
