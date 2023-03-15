<?php

namespace App\Http\Requests\API\District;

use Illuminate\Foundation\Http\FormRequest;
use Auth;
use Illuminate\Contracts\Validation\Validator;

class CreateRequest extends FormRequest
{
    /**
     * Determine if the District is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        if (!Auth::User()->can('district-create')) {
            return sendError("User don't have permission", [], 403);
        }
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
            'name' => 'required',
        ];
    }


    protected function failedValidation(Validator $validator): void
    {
        sendError('validation error', $validator->errors());
    }
}
