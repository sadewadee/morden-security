<?php

namespace MordenSecurity\Modules\Login;

if (!defined('ABSPATH')) {
    exit;
}

class CaptchaManager
{
    private string $sessionPrefix = 'ms_captcha_';
    private array $config;

    public function __construct()
    {
        $this->config = [
            'captcha_enabled' => get_option('ms_captcha_enabled', true),
            'captcha_type' => get_option('ms_captcha_type', 'math'),
            'captcha_difficulty' => get_option('ms_captcha_difficulty', 'medium')
        ];
    }

    public function renderCaptcha(): string
    {
        if (!$this->config['captcha_enabled']) {
            return '';
        }

        switch ($this->config['captcha_type']) {
            case 'math':
                return $this->renderMathCaptcha();
            case 'text':
                return $this->renderTextCaptcha();
            case 'image':
                return $this->renderImageCaptcha();
            default:
                return $this->renderMathCaptcha();
        }
    }

    public function validateCaptcha(string $userInput): bool
    {
        if (!$this->config['captcha_enabled']) {
            return true;
        }

        $sessionKey = $this->sessionPrefix . session_id();
        $correctAnswer = get_transient($sessionKey);

        if (!$correctAnswer) {
            return false;
        }

        delete_transient($sessionKey);

        return strtolower(trim($userInput)) === strtolower(trim($correctAnswer));
    }

    private function renderMathCaptcha(): string
    {
        $operators = ['+', '-', '*'];
        $operator = $operators[array_rand($operators)];

        switch ($this->config['captcha_difficulty']) {
            case 'easy':
                $num1 = rand(1, 10);
                $num2 = rand(1, 5);
                break;
            case 'hard':
                $num1 = rand(10, 50);
                $num2 = rand(5, 20);
                break;
            default:
                $num1 = rand(1, 20);
                $num2 = rand(1, 10);
        }

        switch ($operator) {
            case '+':
                $answer = $num1 + $num2;
                break;
            case '-':
                if ($num1 < $num2) {
                    list($num1, $num2) = [$num2, $num1];
                }
                $answer = $num1 - $num2;
                break;
            case '*':
                $answer = $num1 * $num2;
                break;
        }

        $sessionKey = $this->sessionPrefix . session_id();
        set_transient($sessionKey, (string) $answer, 300);

        return sprintf(
            '<div class="ms-captcha-container">
                <label for="ms_captcha">%s</label>
                <div class="ms-math-captcha">
                    <span class="ms-math-question">%d %s %d = ?</span>
                    <input type="number" id="ms_captcha" name="ms_captcha" required
                           placeholder="%s" class="ms-captcha-input">
                </div>
                <p class="description">%s</p>
            </div>',
            __('Security Question', 'morden-security'),
            $num1,
            $operator,
            $num2,
            __('Answer', 'morden-security'),
            __('Please solve the math problem to continue', 'morden-security')
        );
    }

    private function renderTextCaptcha(): string
    {
        $questions = [
            ['question' => 'What color is the sky?', 'answer' => 'blue'],
            ['question' => 'How many days in a week?', 'answer' => '7'],
            ['question' => 'What animal says "meow"?', 'answer' => 'cat'],
            ['question' => 'What is the opposite of hot?', 'answer' => 'cold'],
            ['question' => 'How many wheels does a bicycle have?', 'answer' => '2']
        ];

        $selectedQuestion = $questions[array_rand($questions)];

        $sessionKey = $this->sessionPrefix . session_id();
        set_transient($sessionKey, $selectedQuestion['answer'], 300);

        return sprintf(
            '<div class="ms-captcha-container">
                <label for="ms_captcha">%s</label>
                <div class="ms-text-captcha">
                    <p class="ms-captcha-question">%s</p>
                    <input type="text" id="ms_captcha" name="ms_captcha" required
                           placeholder="%s" class="ms-captcha-input">
                </div>
                <p class="description">%s</p>
            </div>',
            __('Security Question', 'morden-security'),
            $selectedQuestion['question'],
            __('Your answer', 'morden-security'),
            __('Please answer the security question to continue', 'morden-security')
        );
    }

    private function renderImageCaptcha(): string
    {
        $captchaText = $this->generateRandomString(5);
        $imageData = $this->generateCaptchaImage($captchaText);

        $sessionKey = $this->sessionPrefix . session_id();
        set_transient($sessionKey, $captchaText, 300);

        return sprintf(
            '<div class="ms-captcha-container">
                <label for="ms_captcha">%s</label>
                <div class="ms-image-captcha">
                    <img src="data:image/png;base64,%s" alt="CAPTCHA" class="ms-captcha-image">
                    <input type="text" id="ms_captcha" name="ms_captcha" required
                           placeholder="%s" class="ms-captcha-input">
                </div>
                <p class="description">%s</p>
            </div>',
            __('Security Code', 'morden-security'),
            $imageData,
            __('Enter the code', 'morden-security'),
            __('Please enter the code shown in the image', 'morden-security')
        );
    }

    private function generateRandomString(int $length): string
    {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $result = '';

        for ($i = 0; $i < $length; $i++) {
            $result .= $characters[rand(0, strlen($characters) - 1)];
        }

        return $result;
    }

    private function generateCaptchaImage(string $text): string
    {
        $width = 120;
        $height = 40;
        $image = imagecreate($width, $height);

        $bgColor = imagecolorallocate($image, 255, 255, 255);
        $textColor = imagecolorallocate($image, 0, 0, 0);
        $noiseColor = imagecolorallocate($image, 200, 200, 200);

        for ($i = 0; $i < 50; $i++) {
            imagesetpixel($image, rand(0, $width), rand(0, $height), $noiseColor);
        }

        for ($i = 0; $i < 5; $i++) {
            imageline($image, rand(0, $width), rand(0, $height),
                     rand(0, $width), rand(0, $height), $noiseColor);
        }

        $x = 10;
        for ($i = 0; $i < strlen($text); $i++) {
            $char = $text[$i];
            $angle = rand(-15, 15);
            $fontSize = rand(12, 16);

            imagettftext($image, $fontSize, $angle, $x, 25, $textColor,
                        ABSPATH . 'wp-includes/fonts/default.ttf', $char);
            $x += 20;
        }

        ob_start();
        imagepng($image);
        $imageData = ob_get_contents();
        ob_end_clean();

        imagedestroy($image);

        return base64_encode($imageData);
    }
}
