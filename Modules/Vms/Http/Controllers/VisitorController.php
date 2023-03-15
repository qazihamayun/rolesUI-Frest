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
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Validator;
use SimpleSoftwareIO\QrCode\Facades\QrCode;
use Illuminate\Support\Facades\Session;


use Hash;
use Auth;


class VisitorController extends Controller
{



    public function print($id)
    {
        $visitor = Visitor::with(['user', 'department', 'gate'])->findorfail($id);
        return view('vms::visitor.print', compact('visitor'));
    }



    public function info($id)
    {
        $visitor = Visitor::where(['id' => $id, 'status' => 3])->first();
        if ($visitor) {
            $reponse = ['success' => true, 'data' => $visitor];
        } else {
            $reponse = ['success' => false, 'data' => null];
        }
        return response()->json($reponse);
    }
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        if ($request->ajax()) {
            $modelData = Visitor::query()->with(['user', 'department'])->has('user');
            $modelData->when($request->has('status'), function ($q) use ($request) {
                return $q->whereIn('status', explode(",", $request->status));
            });
            //query For Gate Status 
            $modelData->when(Auth::user()->hasRole('Computer operator'), function ($q) {
                return $q->where('creator_id', Auth::User()->id);
            });

            //query For visitor Status 
            $modelData->when(Auth::user()->hasRole('visitor'), function ($q) {
                return $q->where('user_id', Auth::User()->id);
            });

            $modelData->orderBy('created_at',  'desc');
            return Datatables::of($modelData)->addColumn('action', function ($row) {
                return '';
            })->rawColumns(['action'])->toJson();
        }
        $data = [
            'title' => 'Visitors List'
        ];
        return view('vms::visitor.index', $data);
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        $data = [
            'title' => 'Create New Visitor',
            'gate' => Gate::get(),
            'department' => Company::get(),
            // 'user' => User::whereHas("roles", function($q){ $q->where("name", "Member"); })->get(),
            'vehcilemanufacturer' => VehcileManufacturer::get(),
        ];
        //  dd($data);
        return view('vms::visitor.create', $data);
    }
    public function epass()
    {
        $data = [
            'title' => 'Epass Visitor',
            'gate' => Gate::get(),
        ];
        return view('vms::visitor.epass', $data);
    }



    /**
     * Store a newly created resource in storage.
     *
     * @param  \App\Http\Requests\StoreVisitorRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {


        // $validator = Validator::make($request->all(), [
        //     'department_id' => 'required',
        //     'gate_id' => 'required',
        //     'cnic' => 'required',
        // ]);
        // if ($validator->fails()) {

        //     Alert::toast('The enter required input  ', 'error')->timerProgressBar();
        //     return redirect()->back();
        // }


        $user = VisitorRegistration::where('cnic', $request->cnic)->first();
        if (!$user) {
            $pass = 1235678;
            $input = $request->all();
            $input['password'] = Hash::make($pass);
            $input['email'] = $request->cnic;
            $input['type'] = 'visitor';
            $user = VisitorRegistration::create($input);
            // $user->assignRole('visitor');
            if ($request->has('profile')) {
                if (!empty($request->profile)) {
                    $user->addMediaFromBase64($request->profile)->usingFileName('user_proifle_' . time() . '.png')->toMediaCollection('user_profile');
                }
            }
            if ($request->has('cnic_front')) {
                if (!empty($request->cnic_front)) {
                    $user->addMediaFromBase64($request->cnic_front)->usingFileName('cnic_front_' . time() . '.png')->toMediaCollection('cnic_front');
                }
            }
            if ($request->has('cnic_back')) {
                if (!empty($request->cnic_back)) {
                    $user->addMediaFromBase64($request->cnic_back)->usingFileName('cnic_back_' . time() . '.png')->toMediaCollection('cnic_back');
                }
            }
        }
        $model = new Visitor();
        $data = $request->all();
        $data['user_id'] = $user->id;
        $data['visiting_date'] = Carbon::today();
        $data['visiting_time'] = Carbon::now();
        $data['creator_id'] = auth()->user()->id;
        $model->fill($data);
        $model->save();

        Session::flash('success', 'New Visitor created successfully');
        return redirect()->route('visitors.create');
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $data = [
            'title' => 'Visitor Details',
            'visitor' => Visitor::findOrFail($id),
        ];
        return view('avms::visitor.show', $data);
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        $gate = Gate::get();
        $department =  Company::get();
        $vehcilemanufacturer = VehcileManufacturer::get();
        $visitor = Visitor::with(['user', 'department', 'gate'])->has('user')->has('department')->findorfail($id);
        return view('vms::visitor.edit', compact('visitor', 'gate', 'department', 'vehcilemanufacturer'));
    }

    public function requpdate(Request $request,  $id)
    {

        $model = Visitor::findorfail($id);
        $visitordata = [
            'department_id' => $request->department_id,
            'gate_id' => $request->gate_id,
            'qrcode' => $request->qrcode,
        ];
        $userdata = [
            'name' => $request->name,
            'cnic' => $request->cnic,
            'email' => $request->cnic,
            'mobile' => $request->mobile,
        ];

        $model->fill($visitordata);
        $model->save();
        $user = VisitorRegistration::where('id', $request->user_id)->first();
        $user->fill($userdata);
        $user->save();
        Session::flash('success', 'The visitor updated Successfully');
        return redirect()->route('visitors.index');
    }
    /**
     * Update the specified resource in storage.
     *
     * @param  \App\Http\Requests\UpdateVisitorRequest  $request
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Visitor $visitor)
    {

        // $visitor->update([
        //     'rejected_reason' => $request->rejected_reason,
        //     'visiting_date' => $request->visiting_date,
        //     'visiting_time' => $request->visiting_time,
        //     'status' => $request->status,
        // ]);
        $visitor->update($request->all());
        // $qr = QrCode::size(100)->generate(base64_encode($visitor->qrcode ?? $visitor->id));
        return sendResponse($visitor);
    }


    public function epass_update(Request $request,)
    {
        $visitor = Visitor::findOrFail($request->visitor_id);
        $data = $request->all();
        $data['status'] = 1;
        $visitor->fill($data);
        $visitor->save();
        return redirect()->route('visitors.index');
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function destroy(Visitor $visitor)
    {
        Session::flash('success', 'Visitor Deleted successfully');
    }
}