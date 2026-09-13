package proxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestCaptchaConcurrent_Stress hammers RequestCaptchaCtx and
// PublishCaptchaAnswer from parallel goroutines. Prefetch runs up to two VK
// fetches concurrently (vkSemaphore), so competing RequestCaptcha callers are
// reachable in production; a publish racing a new request used to hit
// send-on-closed-channel and panic the whole process. Run with -race.
func TestCaptchaConcurrent_Stress(t *testing.T) {
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
				RequestCaptchaCtx(ctx, "https://vk.com/captcha?stress=1", 2*time.Millisecond)
				cancel()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				PublishCaptchaAnswer("tok")
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Leave global state clean for other tests.
	PublishCaptchaAnswer("")
}
