<?php


namespace Modules\EIdentity\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Contracts\Validation\Validator;
class ResendOtpRequest extends FormRequest
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
     * @return array
     */
    public function rules(): array
    {
        return [
            'cnic' => 'required|numeric|digits:13',
        ];
    }

    protected function failedValidation(Validator $validator): void
    {
        sendError('validation error', $validator->errors());
    }
}
