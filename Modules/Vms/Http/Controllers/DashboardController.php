<?php


namespace Modules\Vms\Http\Controllers;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Yajra\Datatables\Datatables;
use Modules\Vms\Entities\User;
use Modules\Vms\Entities\Visitor;
use App\Models\Department;
use Modules\Vms\Entities\VehcileManufacturer;


class DashboardController extends Controller
{

    public function dashboard(Request $request)
    {

        $visitorQuery=Visitor::query();

        // if(auth()->user()->hasRole('Department')||auth()->user()->hasRole('Super Admin'))
        // {
            $requested=Visitor::query()->where(['department_id'=>auth()->user()->department_id,'status'=>2])->count();
            $reject=Visitor::query()->where(['department_id'=>auth()->user()->department_id,'status'=>4])->count();
            $accept=Visitor::query()->where(['department_id'=>auth()->user()->department_id,'status'=>3])->count();
            $visited = Visitor::query()->where(['department_id'=>auth()->user()->department_id,'status'=>1])->count();
        // }

        if(auth()->user()->hasRole('visitor'))
        {
            $total=Visitor::query()->where('user_id',auth()->user()->id)->count();
            $requested=Visitor::query()->where(['user_id'=>auth()->user()->id,'status'=>2])->count();
            $reject=Visitor::query()->where(['user_id'=>auth()->user()->id,'status'=>4])->count();
            $accept=Visitor::query()->where(['user_id'=>auth()->user()->id,'status'=>3])->count();
            $visited = Visitor::query()->where(['user_id'=>auth()->user()->id,'status'=>1])->count();
        }

        if(auth()->user()->hasRole('Computer operator'))
        {
            $total=Visitor::query()->where('creator_id',auth()->user()->id)->count();
            $requested=Visitor::query()->where(['creator_id'=>auth()->user()->id,'status'=>2])->count();
            $reject=Visitor::query()->where(['creator_id'=>auth()->user()->id,'status'=>4])->count();
            $accept=Visitor::query()->where(['creator_id'=>auth()->user()->id,'status'=>3])->count();
            $visited = Visitor::query()->where(['creator_id'=>auth()->user()->id,'status'=>1])->count();
        }

        if(auth()->user()->hasRole('Super Admin'))
        {
            $total=Visitor::query()->count();
            $requested=Visitor::query()->where(['status'=>2])->count();
            $reject=Visitor::query()->where(['status'=>4])->count();
            $accept=Visitor::query()->where(['status'=>3])->count();
            $visited = Visitor::query()->where(['status'=>1])->count();
        }



        return view('vms::index', compact('reject','accept','visited','requested'));

        // return view('app.dashboard.dashboard1', compact('reject','accept','visited','requested'));
    }

    
}