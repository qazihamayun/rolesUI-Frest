<?php

namespace App\Http\Requests\API\Tehsil;

use Illuminate\Foundation\Http\FormRequest;
use Auth;
use Illuminate\Contracts\Validation\Validator;

class CreateRequest extends FormRequest
{
    /**
     * Determine if the Tehsil is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        if (!Auth::User()->can('tehsil-create')) {
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
            'district_id' => 'required',
        ];
    }


    protected function failedValidation(Validator $validator): void
    {
        sendError('validation error', $validator->errors());
    }
}
