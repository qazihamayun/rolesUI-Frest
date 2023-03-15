<?php


namespace  Modules\Vms\Http\Requests\Auth;
use Illuminate\Foundation\Http\FormRequest;

class PasswordChangeRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        $currentGuard = auth()->guard('web')->check() ? 'web' : 'sanctum';
        return [
            'old_password' => 'required|min:8|current_password:' . $currentGuard,
            'new_password' => 'required|min:8|confirmed|different:old_password',
        ];
    }
}
