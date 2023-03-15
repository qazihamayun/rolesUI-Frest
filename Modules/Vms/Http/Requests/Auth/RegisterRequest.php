<?php

namespace  Modules\Vms\Http\Requests\Auth;
use Illuminate\Foundation\Http\FormRequest;
use Auth;
use Illuminate\Contracts\Validation\Validator;
class RegisterRequest extends FormRequest
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
            'name' => 'required|string|max:255',
            'cnic' => 'required|unique:vms.users',
            'password' => 'required|min:8',
            'mobile' => 'required',
        ];
    }

    protected function failedValidation(Validator $validator): void
    {
        sendError('validation error', $validator->errors());
    }
}
