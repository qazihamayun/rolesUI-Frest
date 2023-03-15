<?php

namespace Modules\Vms\Http\Controllers;

use Illuminate\Contracts\Support\Renderable;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Yajra\Datatables\Datatables;
use Modules\Vms\Entities\User;
use Modules\Vms\Entities\Visitor;
use App\Models\Department;
use Carbon\Carbon;

class VmsController extends Controller
{



    /**
     * Display a listing of the resource.
     * @return Renderable
     */

    public function CurrentYearData($status = 0)
    {
        if ($status == 0) {
            return Visitor::query()->count() ?? 0;
        }
        return Visitor::query()->whereYear('created_at',  '=', Carbon::now()->format('Y'))->whereStatus($status)->count() ?? 0;
    }

    public function index()
    {
        // dd(auth()->user());

        $requested = Visitor::query()->where(['status' => 2,'department_id'=>auth()->user()->company_id])->count();
        $reject = Visitor::query()->where(['status' => 4,'department_id'=>auth()->user()->company_id])->count();
        $accept = Visitor::query()->where(['status' => 3,'department_id'=>auth()->user()->company_id])->count();
        $visited = Visitor::query()->where(['status' => 1,'department_id'=>auth()->user()->company_id])->count();
        $total = Visitor::query()->count();


        // get Current Year Info/

        $current_year_data = [
            'requested' => $this->CurrentYearData(2),
            'reject' => $this->CurrentYearData(4),
            'accept' =>  $this->CurrentYearData(3),
            'visited' => $this->CurrentYearData(1),
            'total'  => $this->CurrentYearData(0),
            'source_WEB' => Visitor::query()->where('data_source', 'web')->count(),
            'source_API' => Visitor::query()->where('data_source', 'API')->count(),
            'source_CallCenter' => Visitor::query()->where('data_source', 'call_center')->count(),
        ];

        $data = [
            'title' => 'Dashboard',
            'requested' => $requested,
            'reject' => $reject,
            'accept' => $accept,
            'visited' => $visited,
            'total' => $total,
            'current_year_data' => $current_year_data,

        ];
        return view('vms::index', $data);
    }

    /**
     * Show the form for creating a new resource.
     * @return Renderable
     */
    public function create()
    {
        return view('vms::create');
    }

    /**
     * Store a newly created resource in storage.
     * @param Request $request
     * @return Renderable
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Show the specified resource.
     * @param int $id
     * @return Renderable
     */
    public function show($id)
    {
        return view('vms::show');
    }

    /**
     * Show the form for editing the specified resource.
     * @param int $id
     * @return Renderable
     */
    public function edit($id)
    {
        return view('vms::edit');
    }

    /**
     * Update the specified resource in storage.
     * @param Request $request
     * @param int $id
     * @return Renderable
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     * @param int $id
     * @return Renderable
     */
    public function destroy($id)
    {
        //
    }
}