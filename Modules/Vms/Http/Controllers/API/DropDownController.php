<?php


namespace Modules\Vms\Http\Controllers\API;


use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Modules\Settings\Entities\Company;
use Modules\Vms\Entities\Gate;

class DropDownController extends Controller
{



    public function departments()
    {

        $query = Company::query();
        $data = $query->select('id', 'title')->get();
        return response()->json($data);
    }

    public function gates()
    {

        $query = Gate::query();
        $data = $query->select('id', 'name')->get();
        return response()->json($data);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index($model, Request $request)
    {


        $data = [];
        $query = DB::table($model);

        // get columns for current modal 
        $columns =  DB::getSchemaBuilder()->getColumnListing($model);
        $firstParam = $request->key ?? $columns[0];
        $secondParam = $request->value ?? $columns[1];


        if ($request->has('q')) {
            $search = $request->q;
            $data = $query->select($firstParam, $secondParam)
                ->where($secondParam, 'LIKE', "%$search%")
                ->get();
        } else {
            $data = $query->select($firstParam, $secondParam)
                ->get();
        }
        return response()->json($data);
    }
}
