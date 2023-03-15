<?php

namespace App\Http\Requests\API\Role;

use Illuminate\Foundation\Http\FormRequest;
use Auth;
use Illuminate\Contracts\Validation\Validator;

class CreateRoleRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        if (!Auth::User()->can('role-create')) {
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
