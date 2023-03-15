<?php

namespace Modules\Vms\Http\Controllers\API;

use Modules\Vms\Entities\Visitor;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Modules\Vms\Entities\VisitorRegistration;
use Modules\Vms\Entities\Gate;
use Modules\Settings\Entities\Company;
use Auth;
use Hash;
use Modules\Vms\Http\Requests\API\Visitor\CreateStoreRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Carbon;


class VisitorController extends Controller
{

    public function check_time_slot(Request $request)
    {

        $time = $request->visiting_time;
        $startTime = Carbon::parse($time);
     

        $dateString = $request->visiting_date ?? Carbon::now();
        $carbonDate = Carbon::createFromFormat('Y-m-d', $dateString);
     
        $visitors = Visitor::whereBetween('visiting_time', [$startTime->format('h:i'), $startTime->addMinutes(15)->format('h:i')])->whereDate('visiting_date', $carbonDate)->where('department_id', $request->department_id)->get();


        if (count($visitors) > 0) {
            return sendError("Sorry selected time is already reserved", [], 403);
        } else {
            return sendResponse(null, 'Time slot is avaiable');
        }
    }

    public function dashboard()
    {

        $total = Visitor::query()->where('user_id', Auth::guard('vms_api')->User()->id)->whereIn('status', [1, 2])->count();
        $requests = Visitor::query()->where(['user_id' =>  Auth::guard('vms_api')->User()->id, 'status' => 2])->count();
        $approved = Visitor::query()->where(['user_id' =>  Auth::guard('vms_api')->User()->id, 'status' => 3])->count();
        $rejected = Visitor::query()->where(['user_id' => Auth::guard('vms_api')->User()->id, 'status' => 4])->count();
        $recent = Visitor::query()->where(['user_id' => Auth::guard('vms_api')->User()->id])->limit(10)->get();
        $user = VisitorRegistration::query()->where('id', Auth::guard('vms_api')->User()->id)->first();


        $data = [
            'total' => $total,
            'requests' => $requests,
            'approved' => $approved,
            'rejected' => $rejected,
            'recent' => $recent,
            'user' => $user,
        ];
        return sendResponse($data);
    }



    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {

        $query = Visitor::query();
        if ($request->has('user_id')) {
            $query->where('user_id', Auth::guard('vms_api')->User()->id);
        }
        if ($request->has('status')) {
            $query->where('status', $request->status);
        }

        $data = $query->paginate(20);
        return sendResponse($data);
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */

    /**
     * Store a newly created resource in storage.
     *
     * @param  \App\Http\Requests\StoreVisitorRequest  $request
     * @return \Illuminate\Http\Response
     */
    public function store(CreateStoreRequest $request)
    {

        $model = new Visitor();
        $data = $request->all();
        $data['user_id'] =  Auth::guard('vms_api')->user()->id;
        $data['department_id'] = $request->department_id;
        $data['status'] = 2;
        $data['data_source'] = 'API';
        $model->fill($data);
        $model->save();
        return sendResponse($model, 'Vistor created successfully');
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $data = Visitor::where('user_id', Auth::guard('vms_api')->User()->id)->find($id);
        if ($data) {
            return sendResponse($data);
        } else {
            return sendError("User don't have permission", [], 403);
        }
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function edit(Visitor $visitor)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \App\Http\Requests\UpdateVisitorRequest  $request
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function update(UpdateVisitorRequest $request, Visitor $visitor)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Visitor  $visitor
     * @return \Illuminate\Http\Response
     */
    public function destroy(Visitor $visitor)
    {
        //
    }
}
