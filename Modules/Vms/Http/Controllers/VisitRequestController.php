<?php

namespace Modules\Vms\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Yajra\Datatables\Datatables;
use Modules\Vms\Entities\VisitorRegistration;
use Modules\Vms\Entities\Visitor;
use Modules\Vms\Entities\Gate;
use Modules\Settings\Entities\Company;
use Modules\Vms\Entities\VehcileManufacturer;
use Carbon\Carbon;
use Illuminate\Support\Facades\Validator;
use Hash;
use Auth;


class VisitRequestController extends Controller
{

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */

    public function dashboard(Request $request)
    {
        if ($request->ajax()) {
            $modelData = Visitor::query()->where('user_id', Auth::guard('vms_user')->user()->id)->with(['user']);
            //query For Department Role Status 
            $modelData->when($request->has('status'), function ($q) use ($request) {
                return $q->whereIn('status', explode(",", $request->status));
            });

            $modelData->orderBy('created_at',  'desc');

            return Datatables::of($modelData)->toJson();
        }
        $requested = Visitor::query()->where(['status' => 2, 'creator_id' => Auth::guard('vms_user')->user()->id])->count();
        $reject = Visitor::query()->where(['status' => 4, 'creator_id' => Auth::guard('vms_user')->user()->id])->count();
        $accept = Visitor::query()->where(['status' => 3, 'creator_id' => Auth::guard('vms_user')->user()->id])->count();
        $visited = Visitor::query()->where(['status' => 1, 'creator_id' => Auth::guard('vms_user')->user()->id])->count();
        $total = Visitor::query()->count();
        $data = [
            'title' => 'User Dashboard',
            'requested' => $requested,
            'reject' => $reject,
            'accept' => $accept,
            'visited' => $visited,
            'total' => $total,

        ];

        return view('vms::visitor_request.index', $data);
    }
    public function print($id)
    {
        $visitor = Visitor::with(['user'])->has('user')->findorfail($id);
        return view('vms::visitor_request.print', compact('visitor'));
    }
    public function index(Request $request)
    {
        if ($request->ajax()) {
            $modelData = Visitor::query()->where('user_id', Auth::User()->id)->with(['user', 'department']);

            //query For Department Role Status 
            $modelData->when($request->has('status'), function ($q) use ($request) {
                return $q->whereIn('status', explode(",", $request->status));
            });

            $modelData->orderBy('created_at',  'desc');
            return Datatables::of($modelData)->addColumn('action', function ($row) {
                return customButton($row,  'request', 'visit', true);
            })->rawColumns(['action'])->toJson();
        }
        $requested = Visitor::query()->where(['status' => 2, 'creator_id' => Auth::guard('vms_user')->user()->id])->count();
        $reject = Visitor::query()->where(['status' => 4, 'department_id' => Auth::guard('vms_user')->user()->id])->count();
        $accept = Visitor::query()->where(['status' => 3, 'department_id' => Auth::guard('vms_user')->user()->id])->count();
        $visited = Visitor::query()->where(['status' => 1, 'department_id' => Auth::guard('vms_user')->user()->id])->count();
        $total = Visitor::query()->count();
        $data = [
            'title' => 'User Dashboard',
            'requested' => $requested,
            'reject' => $reject,
            'accept' => $accept,
            'visited' => $visited,
            'total' => $total,

        ];

        return view('vms::visitor_request.index', $data);
    }
    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        $department = Company::get();
        $vehcilemanufacturer = VehcileManufacturer::get();

        $data = [
            'title' => 'Visitor Request',
            'department' => $department,
            'vehcilemanufacturer' => $vehcilemanufacturer,
        ];

        return view('vms::visitor_request.create', $data);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //  dd($request->all());
        $validator = Validator::make($request->all(), [
            'department_id' => 'required',
        ]);
        if ($validator->fails()) {

            return redirect()->back();
        }
        $user_id = Auth::guard('vms_user')->user()->id;
        $status = 2;
        $model = new Visitor();
        $data = $request->all();
        $data['user_id'] = $user_id;
        $data['source'] = 'self';
        $data['status'] = $status;
        $data['creator_id'] = $user_id;
        $model->fill($data);
        $model->save();
        return redirect()->route('my.dashboard');
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}