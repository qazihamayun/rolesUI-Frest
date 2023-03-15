<?php

namespace Modules\Vms\Http\Requests\API\Visitor;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Contracts\Validation\Validator;

class CreateStoreRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules()
    {
        return [
            'department_id' => 'required',
            'type' => 'required',
        ];
    }

    protected function failedValidation(Validator $validator): void
    {
        sendError('validation error', $validator->errors());
    }
}
