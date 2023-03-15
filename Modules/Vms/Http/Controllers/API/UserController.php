<?php


namespace Modules\Vms\Http\Controllers\API;


use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Modules\Vms\Entities\VisitorRegistration;
use Spatie\Permission\Models\Role;
use DB;
use Hash;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Auth;
use App\Http\Requests\API\User\CreateRequest;
use App\Http\Requests\API\User\UpdateRequest;

class UserController extends Controller
{


    public function details()
    {
        $user = VisitorRegistration::find(Auth::guard('vms_api')->User()->id);
        return sendResponse($user);
    }
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {

        if (!Auth::User()->can('user-list')) {
            return sendError("User don't have permission", [], 403);
        }
        $query = User::query();
        if ($request->has('filter')) {
        }
        $query->with('roles');
        $data = $query->paginate(20);
        return sendResponse($data);
    }


    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(CreateRequest $request)
    {
        $input = $request->all();
        $input['email_verified_at'] = Carbon::now();
        $input['password'] = Hash::make($input['password']);
        $user = User::create($input);
        $user->assignRole($request->input('roles'));
        return sendResponse($user, 'User created successfully');
    }


    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $model = User::findorfail($id);
        return sendResponse($model, '');
    }




    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        $user = User::find($id);
        $roles = Role::pluck('name', 'name')->all();
        $userRole = $user->roles->pluck('name', 'name')->all();
        return sendResponse(compact('user', 'roles', 'userRole'), 'User updated successfully');
    }


    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(UpdateRequest $request, $id)
    {
        $input = $request->all();
        if (!empty($input['password'])) {
            $input['password'] = Hash::make($input['password']);
        } else {
            $input = Arr::except($input, array('password'));
        }
        $user = User::find($id);
        $user->update($input);
        DB::table('model_has_roles')->where('model_id', $id)->delete();
        $user->assignRole($request->input('roles'));
        return sendResponse($user, 'User updated successfully');
    }


    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        if (!Auth::User()->can('user-delete')) {
            return sendError("User don't have permission", [], 403);
        }
        $user = User::findorfail($id)->delete();
        return sendResponse($user, 'User deleted successfully');
    }
}
