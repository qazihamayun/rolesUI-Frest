<?php

namespace Modules\Vms\Http\Controllers;


use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Modules\Settings\Entities\Company;
use Illuminate\Support\Carbon;
use Modules\Vms\Entities\Visitor;
use Modules\Vms\Entities\Gate;
use DB;

class ReportController extends Controller
{

    // function __construct()
    // {
    //     $this->middleware('permission:report-list|report-create|report-edit|report-delete', ['only' => ['index', 'store', 'visitors']]);
    //     $this->middleware('permission:report-create', ['only' => ['create', 'store']]);
    //     $this->middleware('permission:report-edit', ['only' => ['edit', 'update']]);
    //     $this->middleware('permission:report-delete', ['only' => ['destroy']]);
    // }

    public function visitors(Request $request)
    {

        $from = date('Y-m-d');
        $to = date('Y-m-d');

        if ($request->has('from_date')) {
            $from = $request->from_date;
        }
        if ($request->has('to_date')) {
            $to = $request->to_date;
        }


        $startDate = Carbon::createFromFormat('Y-m-d', $from)->startOfDay();
        $endDate = Carbon::createFromFormat('Y-m-d',  $to)->endOfDay();
        $cond = [$startDate, $endDate];


        $total = Visitor::whereBetween('created_at', $cond)->count();


        $departments = Company::leftJoin('vms.visitors', 'companies.id', '=', 'visitors.department_id')
            ->select('companies.*', DB::raw('COUNT(visitors.id) as visitors_count'))
            ->whereBetween('visitors.created_at', $cond)
            ->groupBy('companies.id')
            ->get();


        $gates = Gate::with('visitors')->withCount(['visitors' => function ($q) use ($cond) {
            $q->whereBetween('created_at', $cond);
        }])->get();


        $data = [
            'total' => $total,
            'departments' => $departments,
            'gates' => $gates,
            'from' => $from,
            'to' => $to,
            'title' =>  "Daily Visitor Reports"
        ];
        return view('vms::reports.visitors', $data);
    }
}
